
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout, get_user_model
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import AuthenticationForm
from django.core.mail import send_mail
from django.conf import settings
from django.views.decorators.http import require_POST

from .forms import RegisterForm
from .utils import generate_numeric_otp, verify_numeric_otp
from .models import OTP

User = get_user_model()


def register(request):
    """
    Show registration form, create inactive user, send OTP to email, and
    ask user to verify OTP. Saves pending user id + otp id in session.
    """
    if request.user.is_authenticated:
        return redirect('auth_app:dashboard')

    if request.method == "POST":
        form = RegisterForm(request.POST)
        if form.is_valid():
            # Save user as inactive
            user = form.save(commit=True)  
            # Create OTP for this user's email
            otp_obj, code = generate_numeric_otp(identifier=user.email, user=user)
            # Send OTP email (dev: console backend)
            send_mail(
                subject="Your Registration OTP",
                message=f"Your OTP to activate your account is: {code}. It expires in 5 minutes.",
                from_email=getattr(settings, "DEFAULT_FROM_EMAIL", "no-reply@example.com"),
                recipient_list=[user.email],
                fail_silently=False,
            )
            # Store pending info in session
            request.session['pending_user_id'] = str(user.pk)
            request.session['otp_id'] = str(otp_obj.id)
            messages.info(request, "An OTP has been sent to your email. Please verify to complete registration.")
            return redirect('auth_app:verify_register_otp')
        else:
            messages.error(request, "Please correct the errors below.")
    else:
        form = RegisterForm()

    return render(request, 'auth/register.html', {'form': form})


def login_view(request):
    if request.user.is_authenticated:
        return redirect('auth_app:dashboard')

    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            messages.success(request, f'Welcome back, {user.username}!')
            next_url = request.POST.get('next') or request.GET.get('next')
            return redirect(next_url or 'auth_app:dashboard')
        else:
            pass
    else:
        form = AuthenticationForm()
    return render(request, 'auth/login.html', {'form': form})


@login_required
def dashboard(request):
    return render(request, 'auth/dashboard.html')


@login_required
def logout_view(request):
    logout(request)
    messages.success(request, 'You have been logged out.')
    return redirect('auth_app:login')


def verify_register_otp(request):
    """
    Page where user submits OTP to activate their account created during registration.
    The user and otp ids are stored in session by register view.
    """
    pending_user_id = request.session.get('pending_user_id')
    otp_id = request.session.get('otp_id')

    if not pending_user_id or not otp_id:
        messages.info(request, "No pending registration found. Please register first.")
        return redirect('auth_app:register')

    # fetch objects safely
    try:
        user = User.objects.get(pk=pending_user_id)
    except User.DoesNotExist:
        messages.error(request, "Pending user not found. Please register again.")
        # cleanup
        request.session.pop('pending_user_id', None)
        request.session.pop('otp_id', None)
        return redirect('auth_app:register')

    try:
        otp_obj = OTP.objects.get(id=otp_id)
    except OTP.DoesNotExist:
        messages.error(request, "OTP not found. Please request a new OTP.")
        return redirect('auth_app:register')

    if request.method == "POST":
        code = request.POST.get("code", "").strip()
        ok, msg = verify_numeric_otp(otp_obj, code)
        if ok:
            # Activate user & login
            user.is_active = True
            user.save(update_fields=['is_active'])
            # Clean session keys
            request.session.pop('pending_user_id', None)
            request.session.pop('otp_id', None)
            login(request, user, backend='django.contrib.auth.backends.ModelBackend')
            messages.success(request, "Your account has been activated and you are now logged in.")
            return redirect('auth_app:dashboard')
        else:
            # show error message but stay on the page so user can retry
            return render(request, 'auth/verify_register_otp.html', {'error': msg})

    return render(request, 'auth/verify_register_otp.html')


@require_POST
def resend_register_otp(request):
    """
    Resend OTP for the pending registration. POST only.
    Use a cooldown/rate-limit in production.
    """
    pending_user_id = request.session.get('pending_user_id')
    if not pending_user_id:
        messages.error(request, "No pending registration to resend OTP for.")
        return redirect('auth_app:register')

    try:
        user = User.objects.get(pk=pending_user_id)
    except User.DoesNotExist:
        request.session.pop('pending_user_id', None)
        messages.error(request, "Pending user not found.")
        return redirect('auth_app:register')

    # Option A: create a new OTP and replace the session otp_id
    otp_obj, code = generate_numeric_otp(identifier=user.email, user=user)
    # send email
    send_mail(
        subject="Your new Registration OTP",
        message=f"Your new OTP is: {code}. It expires in 5 minutes.",
        from_email=getattr(settings, "DEFAULT_FROM_EMAIL", "no-reply@example.com"),
        recipient_list=[user.email],
        fail_silently=False,
    )
    request.session['otp_id'] = str(otp_obj.id)
    messages.success(request, "A new OTP has been sent to your email.")
    return redirect('auth_app:verify_register_otp')

def request_otp_email(request):
    """
    For passwordless login using email OTP.
    User enters email → OTP sent → verify page.
    """
    if request.method == "POST":
        email = request.POST.get("email", "").strip().lower()
        if not email:
            return render(request, "auth/request_otp.html", {"error": "Enter email."})

        # Find existing user only, DO NOT auto-create (to avoid bypassing registration)
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            messages.error(request, "No account found with this email. Please register first.")
            return redirect('auth_app:register')

        # Generate OTP
        otp_obj, code = generate_numeric_otp(identifier=email, user=user)

        # Send OTP
        send_mail(
            subject="Your Login OTP",
            message=f"Your OTP for login is {code}. It expires in 5 minutes.",
            from_email=getattr(settings, "DEFAULT_FROM_EMAIL", "no-reply@example.com"),
            recipient_list=[email],
            fail_silently=False,
        )

        # Save OTP ID in session
        request.session['otp_id'] = str(otp_obj.id)
        return redirect('auth_app:verify_otp')

    return render(request, "auth/request_otp.html")


def verify_otp_view(request):
    """
    Verify OTP for passwordless login.
    """
    otp_id = request.session.get('otp_id')
    if not otp_id:
        messages.info(request, "Please request an OTP first.")
        return redirect('auth_app:request_otp')

    try:
        otp_obj = OTP.objects.get(id=otp_id)
    except OTP.DoesNotExist:
        messages.error(request, "OTP not found. Please request a new OTP.")
        return redirect('auth_app:request_otp')

    if request.method == "POST":
        code = request.POST.get("code", "").strip()
        ok, msg = verify_numeric_otp(otp_obj, code)

        if ok:
            user = otp_obj.user
            login(request, user, backend='django.contrib.auth.backends.ModelBackend')

            # clean session
            request.session.pop('otp_id', None)

            messages.success(request, "Logged in successfully via OTP.")
            return redirect('auth_app:dashboard')

        return render(request, "auth/verify_otp.html", {"error": msg})

    return render(request, "auth/verify_otp.html")
