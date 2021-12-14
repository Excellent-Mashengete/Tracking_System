from django import forms
from .models import Lecturer, Student


class UpdateForm(forms.ModelForm):
    class Meta:
        model= Student
        fields= "__all__"

class ReadStudForm(forms.ModelForm):
    class Meta:
        model= Student
        fields= "__all__"
