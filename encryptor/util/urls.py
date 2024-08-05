from django.urls import path
from . import views

app_name = "util"

urlpatterns = [
    path('generate_keys/', views.generate_keys, name='generate_keys'),
    path('encrypt/', views.save_file, name='save_and_encrypt'),
    path('download/', views.download_file, name='download_file'),
]