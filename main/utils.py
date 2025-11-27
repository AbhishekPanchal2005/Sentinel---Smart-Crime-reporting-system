# main/utils.py
from .models import AuditLog
from django.utils import timezone

def log_action(request_or_user, action, target=None, details="", ip=None):
    """
    Generic logger helper.
    - request_or_user: request (preferred) or a user instance
    - action: string key (e.g. "create_report")
    - target: model instance (optional)
    - details: free text
    - ip: optional override for ip address
    """
    user = None
    ip_addr = ""

    # user + ip extraction when request passed
    try:
        if hasattr(request_or_user, "user"):
            user = request_or_user.user
            # get ip if available
            xff = request_or_user.META.get("HTTP_X_FORWARDED_FOR")
            if xff:
                ip_addr = xff.split(",")[0].strip()
            else:
                ip_addr = request_or_user.META.get("REMOTE_ADDR", "")
        else:
            user = request_or_user
    except Exception:
        user = None

    if ip:
        ip_addr = ip

    target_type = target.__class__.__name__ if target is not None else ""
    target_id = getattr(target, "id", None)

    AuditLog.objects.create(
        actor=user if user and getattr(user, "is_authenticated", False) else None,
        action=action,
        target_type=target_type,
        target_id=target_id,
        details=details or "",
        ip_address=ip_addr or "",
    )
