from django import forms
from .models import CrimeReport

class CrimeReportForm(forms.ModelForm):
    class Meta:
        model = CrimeReport
        fields = ['title', 'description', 'location', 'evidence']
        widgets = {
            'title': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter crime title'}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'rows': 4, 'placeholder': 'Describe the incident...'}),
            'location': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter location'}),
            'evidence': forms.ClearableFileInput(attrs={'class': 'form-control'}),
        }



from django import forms
from .models import User
from django.contrib.auth.forms import UserCreationForm

class CitizenRegistrationForm(UserCreationForm):
    full_name = forms.CharField(max_length=100)
    phone = forms.CharField(max_length=15)

    class Meta:
        model = User
        fields = ['full_name', 'phone', 'username', 'password1', 'password2']

    def clean_phone(self):
        phone = self.cleaned_data['phone']
        if not phone.isdigit() or len(phone) != 10:
            raise forms.ValidationError("Enter a valid 10-digit phone number.")
        return phone
