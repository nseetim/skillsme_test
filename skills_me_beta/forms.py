from django import forms

from django.contrib.auth import password_validation
from django.contrib.auth.models import User


class SignupForm(forms.ModelForm):
    password = forms.CharField(label="Password", widget=forms.PasswordInput)
    email = forms.EmailField(max_length=200, help_text='Required', required=True)

    class Meta:
        model = User
        fields = (
            'first_name', 'last_name', 'email', 'username', 'password',
        )


class LoginForm(forms.Form):
    username = forms.CharField(label='username or email', max_length=200, required=True,)
    password = forms.CharField(label='password', widget=forms.PasswordInput)


class PasswordResetRequestForm(forms.Form):
    email = forms.EmailField(max_length=200, help_text='Enter the email you registered with')


class PasswordResetConfirmForm(forms.Form):
    error_msg = {
        'password_mismatch': 'The two passwords entered do not match'
    }
    new_password = forms.CharField(
        label='New Password', widget=forms.PasswordInput,
        strip=False, help_text=password_validation.password_validators_help_text_html
    )
    confirm_new_password = forms.CharField(
        label='Confirm New Password', widget=forms.PasswordInput,
        strip=False, help_text=password_validation.password_validators_help_text_html
    )

    # So the form can accept the "user" parameter during initialization
    def __init__(self, user, *args, **kwargs):
        self.user = user
        super(PasswordResetConfirmForm, self).__init__(*args, *kwargs)

