from django.urls import path
from . import views

app_name = "util"

urlpatterns = [
    path('generate_keys/', views.generate_keys, name='generate_keys'),
]