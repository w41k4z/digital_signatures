from django import forms
from django.core.validators import FileExtensionValidator

class RegisterForm(forms.Form):
  username = forms.CharField(max_length=100)
  password = forms.CharField(widget=forms.PasswordInput)
  public_key = forms.FileField(
    validators=[FileExtensionValidator(allowed_extensions=['pem'])],
    widget=forms.FileInput(attrs={'accept': '.pem'})
  )

class LoginForm(forms.Form):
  username = forms.CharField(max_length=100)
  password = forms.CharField(widget=forms.PasswordInput)
