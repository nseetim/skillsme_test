from datetime import datetime
import requests

from django.shortcuts import render, redirect
from django.db.models.query_utils import Q
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.cache import never_cache
from django.views.decorators.debug import sensitive_post_parameters
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.core.mail import EmailMessage, BadHeaderError
from django.http import HttpResponse

from .forms import *

# Create your views here.


def index(request):
    return render(request, 'users/index.html')


def signup_user(request):
    if request.user.is_authenticated:
        redirect('index')
    if request.method == 'POST':
        signup_form = SignupForm(data=request.POST)
        if signup_form.is_valid():
            user = signup_form.save(commit=False)
            password = signup_form.cleaned_data['password']
            user.set_password(password)
            user.save()
    signup_form = SignupForm()
    return render(request, 'users/registration.html', {'signup_form': signup_form})


def login_user(request):
    if request.user.is_authenticated:
        redirect('index')
    if request.method == 'POST':
        login_form = LoginForm(data=request.POST)

        if login_form.is_valid():
            username_email = login_form.cleaned_data['username']
            password = login_form.cleaned_data['password']
            # User can login with either username or password
            user_to_match = User.objects.filter(Q(username=username_email) | Q(email=username_email))

            if user_to_match:
                for user in user_to_match:
                    verified_user = authenticate(username=user.username, password=password)
                    login(request, verified_user)
                    messages.success(request, 'Your Login was successful')
                    return redirect('index')
    return render(request, 'users/login.html')


def logout_user(request):
    messages.success(request, 'Log-out successful ')
    logout(request)
    return redirect('/users/login')


@csrf_protect
def password_reset_request(request):
    if request.method == 'POST':
        user_password_reset_form = PasswordResetRequestForm(data=request.POST)
        if user_password_reset_form.is_valid():
            email = user_password_reset_form.cleaned_data['email']
            associated_users = User.objects.filter(
                Q(email__iexact=email, is_active=True, extra_fields__email_is_verified=True)
            )
            if associated_users.exists():
                for user in associated_users:
                    current_site = get_current_site(request)
                    mail_subject = 'Password Reset.'
                    message = render_to_string('users/password_reset_mail.html', {
                        'user': user,
                        'domain': current_site.domain,
                        'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                        'token': default_token_generator.make_token(user)
                    }
                                               )

                    to_email = user.email
                    email = EmailMessage(
                        mail_subject, message, to=[to_email]
                    )
                    try:
                        email.send()
                    except BadHeaderError:
                        return HttpResponse('Invalid header found')
                return render(request, 'users/password_reset_sent.html')
    password_reset_form = PasswordResetRequestForm()
    return render(request, 'users/password_reset_request.html', {'password_reset_form': password_reset_form})


@sensitive_post_parameters()
@never_cache
def password_reset_confirm(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        valid_link = True
        if request.method == 'POST':
            password_reset_confirm_form = PasswordResetConfirmForm(user=user, data=request.POST)
            if password_reset_confirm_form.is_valid():
                    password1 = password_reset_confirm_form.cleaned_data['new_password']
                    password2 = password_reset_confirm_form.cleaned_data['confirm_new_password']
                    if password1 and password2:
                        if password1 != password2:
                            raise password_reset_confirm_form.error_msg['password_mismatch']
                    password_validation.validate_password(password2, user)
                    user.set_password(password2)
                    password_validation.password_changed(password2, user=user)
                    user.save()
                    return render(request, 'users/password_reset_successful.html')
        else:
            password_reset_confirm_form = PasswordResetConfirmForm(user)
    else:
        valid_link = False
        password_reset_confirm_form = None
    context = {
            'password_reset_confirm_form': password_reset_confirm_form,
            'valid_link': valid_link
        }
    return render(request, 'users/password_reset_confirm.html', context)


def currently_available_flights(request):
    now = datetime.now().time()
    #integer_time = int(now.strftime())
    API = "https://opensky-network.org/api/states/all"
    #parameters = integer_time
    response = requests.get(API)
    data = response.json()
    context = {
        'time': data['time'],
        'state': data['states'][2],
        'fullinfo': data['states']
    }
    #print(context)
    return render(request, 'users/current_flights.html', context)

