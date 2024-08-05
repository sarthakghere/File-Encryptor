from django.shortcuts import render
from django.http import HttpResponse, FileResponse
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import datetime
import os
import shutil
# Create your views here.
def generate_keys(request):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    now = datetime.datetime.now()
    directory = f'util/media/files/user_keys_{now.strftime("%Y%m%d%H%M%S")}'
    public_key = private_key.public_key()
    
    private_key_path = os.path.join(directory, 'private_key.pem')
    public_key_path = os.path.join(directory, 'public_key.pem')

    os.makedirs(directory, exist_ok=True)

    # Save the private key
    with open(f"{private_key_path}", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Save the public key
    with open(f"{public_key_path}", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    shutil.make_archive(directory, 'zip', directory)
    shutil.rmtree(directory)
    
    return FileResponse(open(f"{directory}.zip", 'rb'), content_type='application/zip')