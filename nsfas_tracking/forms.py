from django import forms
from .models import AuthUser, Lecturer, Student
from bootstrap_modal_forms.forms import BSModalModelForm

class UpdateForm(forms.ModelForm):
    class Meta:
        model= Student
        fields= "__all__"

class ReadStudForm(forms.ModelForm):
    class Meta:
        model= Student
        fields= "__all__"

class BookModelForm(BSModalModelForm):
    class Meta:
        model = Student
        fields= "__all__"

class StudModelForm(BSModalModelForm):
    class Meta:
        model = AuthUser
        fields= "__all__"

