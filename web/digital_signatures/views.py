import os
from django.views import View
from django.conf import settings
from django.contrib import messages
from django.http import FileResponse
from .forms import RegisterForm, LoginForm
from django.views.generic import TemplateView
from django.shortcuts import render, redirect
from django.contrib.auth.hashers import make_password
from .utils import register_user, authenticate_user, get_unsigned_files, get_signed_files, verify_signature

class HomeView(TemplateView):
  template_name = 'home.html'

  def get_context_data(self, **kwargs):
    return {
      'title': 'Soniavo',
      'description': 'Secure PKI management system',
      'unsigned_files': get_unsigned_files() if self.request.session.get('authenticated') else []
    }

class RegisterView(View):
  template_name = 'register.html'
  form_class = RegisterForm

  def get(self, request):
    return render(request, self.template_name, {'form': self.form_class()})

  def post(self, request):
    form = self.form_class(request.POST, request.FILES)
    if not form.is_valid():
      return render(request, self.template_name, {'form': form})
        
    success, message = register_user(
      username=form.cleaned_data['username'],
      password=form.cleaned_data['password'],
      public_key=form.cleaned_data['public_key']
    )
    
    if success:
      messages.success(request, message)
      return redirect('home')
    else:
      messages.error(request, message)
      return render(request, self.template_name, {'form': form})

class LoginView(View):
  template_name = 'login.html'
  form_class = LoginForm

  def get(self, request):
    if request.session.get('authenticated'):
      return redirect('home')
    return render(request, self.template_name, {'form': self.form_class()})

  def post(self, request):
    form = self.form_class(request.POST)
    if form.is_valid():
      if authenticate_user(
        form.cleaned_data['username'],
        form.cleaned_data['password']
      ):
        request.session['authenticated'] = True
        request.session['username'] = form.cleaned_data['username']
        return redirect('home')
        
    messages.error(request, 'Invalid credentials')
    return render(request, self.template_name, {'form': form})

class DownloadFileView(View):
  def get(self, request, folder, filename):
    if not request.session.get('authenticated'):
      return redirect('login')
        
    file_path = os.path.join(settings.BASE_DIR, 'files', folder, filename)
    return FileResponse(open(file_path, 'rb'), as_attachment=True)

class SignFileView(View):
  template_name = "sign_file.html"
  
  def get(self, request, folder, filename):
    if not request.session.get('authenticated'):
      return redirect('login')
        
    context = {
      'folder': folder,
      'filename': filename,
      'filepath': os.path.join(folder, filename)
    }
    return render(request, self.template_name, context)
  
  def post(self, request, folder, filename):
    if not request.session.get('authenticated'):
      return redirect('login')
        
    file_path = os.path.join(settings.BASE_DIR, 'files', folder, filename)
    signature_file = request.FILES.get('signature')
    
    if not signature_file or not signature_file.name.endswith('.signature.json'):
      messages.error(request, 'Invalid signature file')
      return redirect('home')
    
    success, message = verify_signature(
      request.session['username'],
      file_path,
      signature_file
    )
    
    if success:
      messages.success(request, message)
    else:
      messages.error(request, message)
    
    return redirect('home')

class SignedFilesView(TemplateView):
  template_name = "signed_files.html"
  
  def get_context_data(self, **kwargs):
    context = super().get_context_data(**kwargs)
    context['signed_files'] = get_signed_files() if self.request.session.get('authenticated') else []
    return context

def logout_view(request):
  request.session.flush()
  return redirect('home')
