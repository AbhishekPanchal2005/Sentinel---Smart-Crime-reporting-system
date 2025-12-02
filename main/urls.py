from django.urls import path, include
from rest_framework import routers
from . import views

router = routers.DefaultRouter()
router.register(r'api/reports', views.CrimeReportViewSet)

urlpatterns = [

    # -------------------------
    # AUTHENTICATION
    # -------------------------
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('register/', views.register, name='register'),
    path('audit-log/', views.audit_log, name='audit_log'),
    path("create-admin/", views.create_admin, name="create_admin"),




    # -------------------------
    # MAIN PAGES
    # -------------------------
    path('', views.landing, name='landing'),      # Landing Page
    path('home/', views.home, name='home'),       # Dashboard

    # -------------------------
    # REPORT OPERATIONS
    # -------------------------
    path('report/', views.report_crime, name='report_crime'),
    path('report/<int:report_id>/', views.report_detail, name='report_detail'),
    path('update_status/<int:report_id>/', views.update_status, name='update_status'),
    path('assign/<int:report_id>/', views.assign_report, name='assign_report'),
    path("report/<int:report_id>/pdf/", views.download_report_pdf, name="download_report_pdf"),
    path('export-csv/', views.export_csv, name='export_csv'),


    # -------------------------
    # MAP & API
    # -------------------------
    path('map/', views.crime_map, name='crime_map'),
    path('map-data/', views.map_data, name='map_data'),

    # -------------------------
    # REST API ROUTER
    # -------------------------
    path('api/', include(router.urls)),
]
