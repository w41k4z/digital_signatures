"""
URL configuration for digital_signatures project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from .views import (
    HomeView, 
    RegisterView,
    DownloadFileView, 
    SignFileView,
    SignedFilesView,
    LoginView,
    logout_view
)


urlpatterns = [
    path('admin/', admin.site.urls),
    path('', HomeView.as_view(), name='home'),
    path('register/', RegisterView.as_view(), name='register'),
    path('download/<str:folder>/<str:filename>/', DownloadFileView.as_view(), name='download_file'),
    path('sign/<str:folder>/<str:filename>/', SignFileView.as_view(), name='sign_file'),
    path('signed-documents/', SignedFilesView.as_view(), name='signed_docs'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', logout_view, name='logout'),
]
