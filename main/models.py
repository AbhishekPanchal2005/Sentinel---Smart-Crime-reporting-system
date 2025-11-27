from django.db import models
from django.contrib.auth.models import AbstractUser

# Custom user model with role
class User(AbstractUser):
    ROLE_CHOICES = [
        ('citizen', 'Citizen'),
        ('police', 'Police'),
        ('admin', 'Admin'),
    ]
    full_name = models.CharField(max_length=100, default="")
    phone = models.CharField(max_length=15, unique=True, null=True, blank=True)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='citizen')


    def __str__(self):
        return f"{self.username} ({self.role})"


# Crime report model
class CrimeReport(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('investigating', 'Investigating'),
        ('resolved', 'Resolved'),
    ]

    title = models.CharField(max_length=200)
    description = models.TextField()
    location = models.CharField(max_length=200)
    latitude = models.FloatField(null=True, blank=True)
    longitude = models.FloatField(null=True, blank=True)
    evidence = models.FileField(upload_to='evidence/', null=True, blank=True)  # ✅ new field
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    reporter = models.ForeignKey(User, on_delete=models.CASCADE)
    date_reported = models.DateTimeField(auto_now_add=True)
    crime_type = models.CharField(max_length=100, null=True, blank=True)
    severity = models.CharField(max_length=10, null=True, blank=True)
    priority = models.CharField(max_length=20, null=True, blank=True)
    summary = models.TextField(null=True, blank=True)
    llm_confidence = models.FloatField(null=True, blank=True)
    assigned_to = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name="assigned_reports")



    def __str__(self):
        return f"{self.title} ({self.status})"
    

from django.contrib.auth import get_user_model

User = get_user_model()

class AuditLog(models.Model):
    """Simple audit log for important actions."""
    ACTION_CHOICES = [
        ("create_report", "Create Report"),
        ("update_status", "Update Status"),
        ("assign_report", "Assign Report"),
        ("login", "Login"),
        ("logout", "Logout"),
        ("delete_report", "Delete Report"),
        ("other", "Other"),
    ]

    actor = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    action = models.CharField(max_length=50, choices=ACTION_CHOICES, default="other")
    target_type = models.CharField(max_length=50, blank=True)   # e.g. "CrimeReport"
    target_id = models.IntegerField(null=True, blank=True)
    details = models.TextField(blank=True)
    ip_address = models.CharField(max_length=45, blank=True)  # optional
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        who = self.actor.username if self.actor else "System"
        return f"{self.created_at:%Y-%m-%d %H:%M} | {who} | {self.action}"
