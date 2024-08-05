from django import forms

class FileUploadForm(forms.Form):
    file = forms.FileField(label='File to encrypt')
    publicKey = forms.FileField(label='Receiver\'s Public Key')
