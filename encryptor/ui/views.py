from django.shortcuts import render, redirect
from django.http import HttpResponse
from .forms import FileUploadForm


# Create your views here.
def index(request):
    return render(request, 'ui/base.html')

def encrypt_ui(request):
    form = FileUploadForm()
    return render(request, 'ui/encrypt.html', {'form': form})

# def decrypt_ui(request):
#     return render(request, 'ui/decrypt.html')

def success(request):
    encrypted_file_path = request.session.get('encrypted_file_path')
    context = {'encrypted_file_path': encrypted_file_path}
    return render(request, 'ui/success.html', context)
