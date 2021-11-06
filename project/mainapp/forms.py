from django.forms import ModelForm
from django import forms
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError

from .models import GenericModelMain, GenericModelForeign

# date widget = forms.DateInput(attrs={'type': 'date'})
# datetime widget = forms.DateInput(attrs={'type': 'datetime-local'})

class GenericModelMainForm(ModelForm):
    class Meta:
        model = GenericModelMain
        fields = '__all__'
        exclude = ['employment_date','termination_date']
        widgets = {
            'birth_date': forms.DateInput(attrs={'type': 'date'}),
        }


class GenericModelForeignForm(ModelForm):
    class Meta:
        model = GenericModelForeign
        fields = '__all__'

class CustomUserCreationForm(forms.Form):
    username = forms.CharField(label='Username', min_length=4, max_length=150)
    first_name = forms.CharField(label='First name', min_length=4, max_length=150)
    last_name = forms.CharField(label='Last name', min_length=4, max_length=150)
    email = forms.EmailField(label='Email address')
    password1 = forms.CharField(label='Password', widget=forms.PasswordInput)
    password2 = forms.CharField(label='Confirm password', widget=forms.PasswordInput)

    def clean_username(self):
        username = self.cleaned_data['username'].lower()
        r = User.objects.filter(username=username)
        if r.count():
            raise ValidationError("Username already exists.")
        return username

    def clean_email(self):
        email = self.cleaned_data['email'].lower()
        r = User.objects.filter(email=email)
        if r.count():
            raise ValidationError("Email already exists.")
        return email

    def clean_password2(self):
        password1 = self.cleaned_data.get('password1')
        password2 = self.cleaned_data.get('password2')

        if password1 and password2 and password1 != password2:
            raise ValidationError("Password don't match.")

        return password2

    def save(self, commit=True):
        user = User.objects.create_user(
            self.cleaned_data['username'],
            self.cleaned_data['email'],
            self.cleaned_data['password1'],
        )
        user.first_name = self.cleaned_data['first_name']
        user.last_name = self.cleaned_data['last_name']
        user.save()
        return user

class LoginForm(forms.Form):
    username = username = forms.CharField(label='Username')
    password = forms.CharField(label='Password', widget=forms.PasswordInput)

class PasswordResetForm(forms.Form):
    email = forms.EmailField(label='Email')

class PasswordResetConfirmForm(forms.Form):
    password1 = forms.CharField(label='Password', widget=forms.PasswordInput)
    password2 = forms.CharField(label='Confirm password', widget=forms.PasswordInput)

    def clean_password2(self):
        password1 = self.cleaned_data.get('password1')
        password2 = self.cleaned_data.get('password2')

        if password1 and password2 and password1 != password2:
            raise ValidationError("Password don't match.")

        return password2