# ===========================
# IMPORTS
# ===========================
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse, HttpResponseForbidden
from django.utils.dateparse import parse_datetime
from django.db.models import Count
from django.db.models.functions import TruncMonth
from .utils import log_action
from .models import CrimeReport, User
from .forms import CrimeReportForm, CitizenRegistrationForm

from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import user_passes_test
User = get_user_model()
from .models import AuditLog

from geopy.geocoders import Nominatim
from openai import OpenAI
import os, json, re
from datetime import datetime

from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from django.http import HttpResponse


# ===========================
# LANDING PAGE
# ===========================
def landing(request):
    if request.user.is_authenticated:
        return redirect('home')
    return render(request, 'landing.html')


# ===========================
# USER REGISTRATION
# ===========================
def register(request):
    if request.method == "POST":
        form = CitizenRegistrationForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.role = "citizen"
            user.save()
            login(request, user)
            messages.success(request, "Registration successful!")
            return redirect('home')
    else:
        form = CitizenRegistrationForm()

    return render(request, 'register.html', {"form": form})


# ===========================
# LOGIN VIEW
# ===========================
def login_view(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        user = authenticate(request, username=username, password=password)

        if user:
            login(request, user)
            return redirect("landing")
        else:
            messages.error(request, "Invalid username or password.")

    return render(request, "login.html")


# ===========================
# LOGOUT
# ===========================
def logout_view(request):
    logout(request)
    return redirect("login")


# ===========================
# DASHBOARD (HOME)
# ===========================
@login_required(login_url='login')
def home(request):
    user = request.user
    filter_status = request.GET.get("status")

    # Role-based data:
    if user.role == "admin":
        reports = CrimeReport.objects.all()
        title = "Admin Dashboard - All Reports"
        police_users = User.objects.filter(role="police")

    elif user.role == "police":
        reports = CrimeReport.objects.exclude(status="resolved")
        title = "Police Dashboard - Active Cases"
        police_users = []

    else:
        reports = CrimeReport.objects.filter(reporter=user)
        title = "Citizen Dashboard - My Reports"
        police_users = []

    # Apply filter
    if filter_status in ["pending", "investigating", "resolved"]:
        reports = reports.filter(status=filter_status)

    reports = reports.order_by("-date_reported")

    # Analytics:
    status_counts = reports.values("status").annotate(total=Count("status"))
    monthly_data = reports.annotate(month=TruncMonth("date_reported")).values("month").annotate(count=Count("id"))
    
    # Fixed crime_type_data - exclude None/empty values and ensure uniqueness
    crime_type_data = (
        reports.exclude(crime_type__isnull=True)
        .exclude(crime_type="")
        .values("crime_type")
        .annotate(count=Count("id"))
        .order_by("-count")
    )
    
    # Fixed priority_data - exclude None/empty values, ensure case-insensitive grouping
    priority_data = (
        reports.exclude(priority__isnull=True)
        .exclude(priority="")
        .values("priority")
        .annotate(count=Count("id"))
    )
    
    # Deduplicate and normalize priority data (in case of case sensitivity issues)
    priority_map = {}
    for item in priority_data:
        # Normalize to Title Case
        normalized_priority = item["priority"].capitalize() if item["priority"] else "Unknown"
        if normalized_priority in priority_map:
            priority_map[normalized_priority] += item["count"]
        else:
            priority_map[normalized_priority] = item["count"]
    
    # Sort priorities in logical order: High, Medium, Low
    priority_order = {"High": 1, "Medium": 2, "Low": 3}
    sorted_priorities = sorted(
        priority_map.items(), 
        key=lambda x: priority_order.get(x[0], 99)
    )

    chart_data = {
        "crime_type_labels": [d["crime_type"] for d in crime_type_data],
        "crime_type_counts": [d["count"] for d in crime_type_data],
        "priority_labels": [p[0] for p in sorted_priorities],
        "priority_counts": [p[1] for p in sorted_priorities],
        "month_labels": [d["month"].strftime("%b %Y") for d in monthly_data],
        "month_counts": [d["count"] for d in monthly_data],
    }

    context = {
        "reports": reports,
        "title": title,
        "status_counts": status_counts,
        "chart_data": json.dumps(chart_data),
        "filter_status": filter_status,
        "police_users": police_users,
    }

    return render(request, "home.html", context)



# admin-only view (police may also view logs if you prefer)
@user_passes_test(lambda u: hasattr(u, "role") and u.role == "admin")
def audit_log(request):
    # optional filters: action, actor, since
    qs = AuditLog.objects.all().select_related("actor")

    action = request.GET.get("action")
    actor = request.GET.get("actor")
    if action:
        qs = qs.filter(action=action)
    if actor:
        qs = qs.filter(actor__username__icontains=actor)

    qs = qs.order_by("-created_at")[:500]  # cap to 500 rows

    actions = AuditLog.ACTION_CHOICES

    return render(request, "audit_log.html", {"logs": qs, "actions": actions})



from django.http import HttpResponseForbidden

@login_required
def assign_report(request, report_id):
    if request.user.role != "admin":
        return HttpResponseForbidden("Not allowed")

    report = get_object_or_404(CrimeReport, id=report_id)

    if request.method == "POST":
        user_id = request.POST.get("assigned_to")
        if user_id:
            police_user = User.objects.get(id=user_id)
            report.assigned_to = police_user
        else:
            report.assigned_to = None

        report.save()
        assignee = getattr(report, "assigned_to", None)
        assignee_text = assignee.username if assignee else "Unassigned"
        log_action(request, "assign_report", target=report,
                details=f"Assigned to: {assignee_text}")

        messages.success(request, "Case assignment updated successfully!")
        return redirect('home')

    # default (GET request)
    police_users = User.objects.filter(role="police")
    return render(request, "assign_report.html", {"report": report, "police_users": police_users})

# ===========================
# AI CLIENT
# ===========================
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))


# ===========================
# CRIME REPORT SUBMISSION
# ===========================
@login_required
def report_crime(request):
    if request.method == "POST":
        form = CrimeReportForm(request.POST, request.FILES)

        if form.is_valid():
            report = form.save(commit=False)
            report.reporter = request.user

            # ---------- AI SUMMARY ----------
            prompt = f"""
            Analyze this crime report and return a strict JSON:
            {{
                "summary": "",
                "crime_type": "",
                "confidence": 0.87
            }}

            Report Description:
            "{report.description}"
            """

            try:
                response = client.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=[
                        {"role": "system", "content": "Respond ONLY with JSON. No markdown."},
                        {"role": "user", "content": prompt},
                    ],
                    temperature=0.7,
                )

                ai_text = response.choices[0].message.content.strip()

                clean = re.sub(r"```.*?```", "", ai_text, flags=re.DOTALL).strip()

                try:
                    data = json.loads(clean)
                except:
                    data = {}

                report.summary = data.get("summary", clean)
                report.crime_type = data.get("crime_type", "General")
                report.llm_confidence = data.get("confidence", 0.7)

                # Priority rule
                crime = report.crime_type.lower()
                if crime in ["theft", "robbery", "assault"]:
                    report.priority = "High"
                elif crime in ["fraud", "cybercrime"]:
                    report.priority = "Medium"
                else:
                    report.priority = "Low"

            except Exception as e:
                report.summary = "AI analysis unavailable."
                report.crime_type = "Unclassified"
                report.llm_confidence = 0

            # ---------- Geocoding ----------
            try:
                geo = Nominatim(user_agent="smart_crime_reporting")
                loc = geo.geocode(f"{report.location}, Delhi, India")
                if loc:
                    report.latitude = loc.latitude
                    report.longitude = loc.longitude
            except:
                pass

            report.save()
            log_action(request, "create_report", target=report,
            details=f"Report created: {report.title}")
            messages.success(request, "Report submitted with AI insights!")
            return redirect("home")

    else:
        form = CrimeReportForm()

    return render(request, "report_crime.html", {"form": form})


# ===========================
# REPORT DETAIL VIEW
# ===========================
@login_required
def report_detail(request, report_id):
    report = get_object_or_404(CrimeReport, id=report_id)

    if request.user.role == "citizen" and report.reporter != request.user:
        messages.error(request, "Not authorized.")
        return redirect("home")

    return render(request, "report_detail.html", {"report": report})


# ===========================
# STATUS UPDATE (POLICE/ADMIN)
# ===========================
@login_required
def update_status(request, report_id):
    report = get_object_or_404(CrimeReport, id=report_id)

    if request.user.role not in ("admin", "police"):
        return HttpResponseForbidden("Not allowed.")

    if request.method == "POST":
        status = request.POST.get("status")
        if status:
            report.status = status
            report.save()
            log_action(request, "update_status", target=report,
            details=f"Status changed to {status}")
            messages.success(request, f"Status updated to {status.title()}")

    return redirect("home")


# ===========================
# FINAL MAP VIEW (filters on top)
# ===========================
@login_required
def crime_map(request):
    """
    Renders the map page. The data for markers/heatmap is fetched by the page
    from the map_data endpoint (role-based filtering handled server-side there).
    """
    user = request.user
    show_heatmap = user.role in ("police", "admin")
    # pass filter lists (optional UI perks)
    crime_types = list(CrimeReport.objects.values_list('crime_type', flat=True).distinct())
    priorities = list(CrimeReport.objects.values_list('priority', flat=True).distinct())
    statuses = list(CrimeReport.objects.values_list('status', flat=True).distinct())

    context = {
        "show_heatmap": show_heatmap,
        "crime_types": [c for c in crime_types if c],
        "priorities": [p for p in priorities if p],
        "statuses": [s for s in statuses if s],
    }
    return render(request, "map.html", context)



# ===========================
# MAP MARKER + HEATMAP DATA API
# ===========================
@login_required
def map_data(request):
    user = request.user

    qs = CrimeReport.objects.filter(latitude__isnull=False, longitude__isnull=False)

    if user.role not in ("admin", "police"):
        qs = qs.filter(reporter=user)

    crime_type = request.GET.get("crime_type")
    priority = request.GET.get("priority")
    status = request.GET.get("status")
    since = request.GET.get("since")

    if crime_type and crime_type != "all":
        qs = qs.filter(crime_type__iexact=crime_type)

    if priority and priority != "all":
        qs = qs.filter(priority__iexact=priority)

    if status and status != "all":
        qs = qs.filter(status__iexact=status)

    if since:
        try:
            dt = parse_datetime(since)
            if dt:
                qs = qs.filter(date_reported__gte=dt)
        except:
            pass

    results = []
    for r in qs.order_by('-date_reported')[:1000]:
        results.append({
            "id": r.id,
            "title": r.title,
            'location': r.location,
            "lat": float(r.latitude),
            "lng": float(r.longitude),
            "crime_type": r.crime_type,
            "priority": r.priority,
            "status": r.status,
            "summary": (r.summary or "")[:300],
            "date": r.date_reported.strftime("%Y-%m-%d %H:%M"),
        })

    return JsonResponse({"results": results})

@login_required
def download_report_pdf(request, report_id):
    report = get_object_or_404(CrimeReport, id=report_id)

    # Role-based access: citizens can download only their own reports
    if request.user.role == "citizen" and report.reporter != request.user:
        messages.error(request, "You are not authorized to download this report.")
        return redirect("home")

    # PDF response setup
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="Report_{report.id}.pdf"'

    p = canvas.Canvas(response, pagesize=letter)
    width, height = letter

    y = height - 50

    # Title
    p.setFont("Helvetica-Bold", 18)
    p.drawString(50, y, "Crime Report Summary")
    y -= 40

    def line(text, size=12, offset=20, bold=False):
        nonlocal y
        if bold:
            p.setFont("Helvetica-Bold", size)
        else:
            p.setFont("Helvetica", size)

        for part in text.split("\n"):
            p.drawString(50, y, part)
            y -= offset

    # PDF content
    line(f"Report ID: {report.id}", bold=True)
    line(f"Title: {report.title}")
    line(f"Reporter: {report.reporter.username}")
    line(f"Date Reported: {report.date_reported.strftime('%Y-%m-%d %H:%M')}")
    line(f"Location: {report.location}")
    line(f"Crime Type: {report.crime_type}")
    line(f"Priority: {report.priority}")
    line(f"Status: {report.status}")
    line(f"AI Confidence: {round(report.llm_confidence or 0, 2)}")

    line("", offset=10)
    line("AI Summary:", bold=True)
    line(report.summary or "No AI summary available.", offset=15)

    line("", offset=20)
    line("Evidence File:", bold=True)
    if report.evidence:
        line(f"Attached file: {report.evidence.url}")
    else:
        line("No evidence uploaded.")

    p.showPage()
    p.save()
    return response


import csv
from django.http import HttpResponse

@login_required
def export_csv(request):
    # Only police/admin allowed
    if request.user.role not in ["police", "admin"]:
        messages.error(request, "You are not authorized to export reports.")
        return redirect("home")

    filter_status = request.GET.get("status", "all")

    # Filter reports
    reports = CrimeReport.objects.all()

    if filter_status in ["pending", "investigating", "resolved"]:
        reports = reports.filter(status=filter_status)

    # Prepare CSV
    response = HttpResponse(content_type='text/csv')
    filename = f"crime_reports_{filter_status}.csv"
    response['Content-Disposition'] = f'attachment; filename="{filename}"'

    writer = csv.writer(response)

    writer.writerow([
        "ID", "Title", "Description", "Location", "Latitude", "Longitude",
        "Crime Type", "Priority", "Status", "AI Summary",
        "LLM Confidence", "Date Reported", "Reporter Username"
    ])

    for r in reports:
        writer.writerow([
            r.id,
            r.title,
            r.description,
            r.location,
            r.latitude,
            r.longitude,
            r.crime_type,
            r.priority,
            r.status,
            r.summary,
            r.llm_confidence,
            r.date_reported.strftime("%Y-%m-%d %H:%M"),
            r.reporter.username if r.reporter else "Unknown"
        ])

    return response



from rest_framework import viewsets, permissions
from .serializers import CrimeReportSerializer

class CrimeReportViewSet(viewsets.ModelViewSet):
    queryset = CrimeReport.objects.all().order_by('-date_reported')
    serializer_class = CrimeReportSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(reporter=self.request.user)


from django.contrib.auth import get_user_model
from django.http import HttpResponse

def recreate_admin(request):
    User = get_user_model()

    # credentials you want
    username = "admin2"
    email = "admin2@example.com"
    password = "Admin2025!"

    if User.objects.filter(username=username).exists():
        return HttpResponse("Admin already exists.")

    User.objects.create_superuser(username=username, email=email, password=password)

    return HttpResponse(f"Superuser created: {username} / {password}")




from django.http import HttpResponse, HttpResponseForbidden
from django.contrib.auth import get_user_model
import os

def create_admin(request):
    """
    Temporary route to create a superuser when Render shell is unavailable.
    Protected using a secret key. DELETE THIS after use.
    """
    secret = os.environ.get("CREATE_ADMIN_KEY")
    provided = request.GET.get("key")

    if not secret:
        return HttpResponse("CREATE_ADMIN_KEY is not set on server.", status=500)

    if provided != secret:
        return HttpResponseForbidden("Invalid key.")

    User = get_user_model()

    if User.objects.filter(username="admin").exists():
        return HttpResponse("Admin user already exists.")

    User.objects.create_superuser(
        username="admin",
        email="admin@example.com",
        password="Admin@1234"
    )

    return HttpResponse("Superuser created successfully: admin / Admin@1234")



# add near other admin/debug helpers in main/views.py
import os
from django.http import HttpResponse, HttpResponseForbidden
from django.contrib.auth import get_user_model

def create_demo_users(request):
    """
    One-time protected endpoint to create demo police & admin accounts.
    Use: /create-demo-users/?key=<CREATE_ADMIN_KEY>
    Remove this view and URL after use.
    """
    expected_key = os.environ.get("CREATE_ADMIN_KEY")
    provided_key = request.GET.get("key", "")
    if not expected_key:
        return HttpResponse("CREATE_ADMIN_KEY not configured on server.", status=400)
    if provided_key != expected_key:
        return HttpResponseForbidden("Forbidden: invalid key.")

    User = get_user_model()
    created = []

    # Create police user
    if not User.objects.filter(username="police1").exists():
        User.objects.create_user(
            username="police1",
            email="police1@example.com",
            password="Police@123",
            role="police",
            is_active=True
        )
        created.append("police1/Police@123")

    # Create admin user (superuser + staff)
    if not User.objects.filter(username="admin1").exists():
        try:
            User.objects.create_superuser(
                username="admin1",
                email="admin1@example.com",
                password="Admin@1234",
            )
        except TypeError:
            # fallback for custom create_superuser signature
            user = User.objects.create_user(
                username="admin1",
                email="admin1@example.com",
                password="Admin@1234",
                role="admin",
            )
            user.is_staff = True
            user.is_superuser = True
            user.save()
        created.append("admin1/Admin@1234")

    if not created:
        return HttpResponse("Demo users already exist.", status=200)

    return HttpResponse("Created demo users: " + ", ".join(created), status=201)

