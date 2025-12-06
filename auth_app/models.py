
from django.conf import settings
from django.db import models
from django.utils import timezone
import uuid

class OTP(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.CASCADE)
    identifier = models.CharField(max_length=255)  # email address used for OTP
    code_hash = models.CharField(max_length=128)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used = models.BooleanField(default=False)
    attempts = models.PositiveSmallIntegerField(default=0)

    def is_expired(self):
        return timezone.now() >= self.expires_at

    def __str__(self):
        return f"OTP for {self.identifier} (used={self.used})"
