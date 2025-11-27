from django.contrib import admin
from .models import User, CrimeReport

admin.site.register(User)
admin.site.register(CrimeReport)

# main/admin.py
from django.contrib import admin
from .models import AuditLog

@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ("created_at", "actor", "action", "target_type", "target_id")
    list_filter = ("action", "actor")
    search_fields = ("actor__username", "details", "target_type")

