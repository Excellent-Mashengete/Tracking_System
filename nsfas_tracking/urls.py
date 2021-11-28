from tempfile import template
from django.conf.urls import url
from django.urls import include, path
from . import views

from django.conf.urls.static import static
from django.conf import settings
from django.contrib import admin
from django.contrib.auth import views as auth_views

urlpatterns = [
    path('', views.home, name='home'),
    path('student/', views.student, name='student'),

    path('about/', views.about, name='about'),
    path('contact/', views.contact, name='contact'),
    
    #################################################
    #Microsoft API's Links
    path('signin', views.sign_in, name='signin'),
    path('signout', views.sign_out, name='signout'),
    path('callback', views.callback, name='callback'),
    path('lecture/new', views.newevent, name='newevent'),
    path('lecture/', views.lecture, name='lecture'),
    #################################################

    path('/lecture/attendance/', views.attendence, name='attendance'),
    path('stud_login/', views.stud_login, name='stud_login'),
    path('register/',views.register, name='register'),
    path('nsfas_login/', views.nsfas_login, name='nsfas_login'),
    path('stud_profile', views.stud_profile, name='stud_profile'),
    path('nsfas/', views.nsfas, name = 'nsfas'),
    path('display_login_details/', views.desplay_stud_login, name = 'display_login_details'),
    path('display_stud_data/', views.display_stud_data, name = 'display_stud_data'),
    path("logout_user", views.logout, name='logout_user'),
    path('profile/', views.profile, name='profile'),
    path('stud_profile/', views.stud_profile, name='stud_profile'),
    
    #Reset Password
    path('set-new-password/<uidb64>/<token>', views.CompletePasswordRest, name='reset-user-password'),
    path('request-reset-link', views.RequestPasswordResetEmail, name='reset-password'),

    #Crud Operations
    #Delete and Update student 
    path('delete/<str:pk>', views.delete, name = 'delete'),
    path('update/<int:pk>', views.update, name = 'update'),
    
    #Report for funded students
    path('export_pdf/',views.export_pdf, name='export_pdf'),
    path('export_csv_Students', views.export_csv_Students, name='export_csv_Students'), 
    path('export_excel_students', views.export_excel_students, name='export_excel_students'),
	
    #Report for individual attendance
    path('getIndividualReport/<int:pk>', views.getIndividualReport, name='getIndividualReport'),
    path('IndReport_CSV/', views.IndReport_CSV, name='IndReport_CSV'),
    path('IndReport_WORD/<int:pk>', views.IndReport_WORD, name='IndReport_WORD'),

]