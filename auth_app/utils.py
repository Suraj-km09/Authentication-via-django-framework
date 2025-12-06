
import random
import hashlib
import hmac
from datetime import timedelta
from django.utils import timezone
from .models import OTP

OTP_TTL_SECONDS = 300  # 5 minutes

def _hash_code(code: str) -> str:
    return hashlib.sha256(code.encode()).hexdigest()

def generate_numeric_otp(identifier: str, user=None, ttl_seconds=OTP_TTL_SECONDS):
    code = f"{random.randint(0, 999999):06d}"
    otp = OTP.objects.create(
        user=user,
        identifier=identifier,
        code_hash=_hash_code(code),
        expires_at=timezone.now() + timedelta(seconds=ttl_seconds)
    )
    return otp, code

def verify_numeric_otp(otp_obj: OTP, code: str, max_attempts=5):
    if otp_obj.used:
        return False, "OTP already used"
    if otp_obj.is_expired():
        return False, "OTP expired"
    if otp_obj.attempts >= max_attempts:
        return False, "Too many attempts"
    otp_obj.attempts += 1
    otp_obj.save(update_fields=['attempts'])
    if hmac.compare_digest(otp_obj.code_hash, _hash_code(code)):
        otp_obj.used = True
        otp_obj.save(update_fields=['used'])
        return True, "OK"
    return False, "Incorrect code"
