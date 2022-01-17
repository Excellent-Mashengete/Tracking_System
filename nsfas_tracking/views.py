from __future__ import print_function
import django
from django.contrib.messages.api import success
from django.shortcuts import render, redirect, get_list_or_404,HttpResponseRedirect
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse, FileResponse, response
from django.urls import reverse
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, update_session_auth_hash
from django.contrib import auth, messages
from django.views.decorators.cache import cache_control
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import AuthenticationForm, PasswordChangeForm, PasswordResetForm
import mysql.connector
from django.core.mail import send_mail, BadHeaderError, EmailMessage
from requests.models import codes
from Tracking_System.settings import EMAIL_HOST_USER, EMAIL_FROM_USER
from .models import *
from operator import itemgetter
import pandas as pd
import urllib
import sys
import csv, io
import json
import openpyxl 
import xlwt
import requests
from django.core.paginator import Paginator
import sys
from django.template.loader import get_template, render_to_string
from weasyprint import HTML
import tempfile 
from django.db.models import Count
from xhtml2pdf import context, pisa
from .forms import UpdateForm, ReadStudForm, StudModelForm, BookModelForm
from django.urls import reverse_lazy
from django.views import generic
from bootstrap_modal_forms.generic import (
  BSModalReadView,
  BSModalDeleteView,

)

#for report lab
from reportlab.pdfgen import canvas
from reportlab.lib.units import inch
from reportlab.lib.pagesizes import letter
from reportlab.lib.pagesizes import landscape
from reportlab.platypus import Image

#resert password
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import send_mail, BadHeaderError, EmailMessage
from django.db.models.query_utils import Q
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth.tokens import default_token_generator, PasswordResetTokenGenerator
from django.utils.encoding import force_bytes, force_str, force_text
from Tracking_System.settings import EMAIL_FROM_USER, GOOGLE_RECAPTCHA_SECRET_KEY, GOOGLE_RECAPTCHA_SITE_KEY
from django.views import View

#Ms authentication system
from time import sleep
from datetime import datetime, timedelta
from dateutil import tz, parser
from nsfas_tracking.auth_helper import get_sign_in_flow, get_token_from_code, store_user, remove_user_and_token, get_token
from nsfas_tracking.graph_helper import *

global cursor4
# The landing Page.
def home(request):
	return render(request, "home.html",{})

#The about page
def about(request):
	return render(request, "about.html",{})

#The contact page
def contact(request):
	if request.method == 'POST':
		name = request.POST.get('name')
		email = request.POST.get('email')
		phone = request.POST.get('phone')
		body = request.POST.get('body')

		subject = "Website Inquiry"
		message = 'Full Name: '+name+'\nEmail: '+email+'\nContacts: '+phone+'\n'+body
		try:
			send_mail(subject, message, EMAIL_HOST_USER, [EMAIL_HOST_USER])
			messages.success(request, 'Website inquiry has been logged')
		except BadHeaderError:
			return HttpResponse('Invalid header found.')
	return render(request, 'contact.html', {"recaptcha_site_key":GOOGLE_RECAPTCHA_SITE_KEY})

			#STUDENT 
############################################################################
#Password authentication
def password_check(password):
	specialSym =['$','@','#','%','!']
	context={'has_error':False}

	if len(password) < 6:
		context['has_error'] = True
	if len(password) > 20:
		context['has_error'] = True
	if not any(char.isdigit() for char in password):
		context['has_error'] = True
	if not any(char.isupper() for char in password):
		context['has_error'] = True
	if not any(char.islower() for char in password):
		context['has_error'] = True
	if not any(char in specialSym for char in password):
		context['has_error'] = True

	if context['has_error']:
		return context

#register page
def register(request):
	if request.method == 'POST':
		context={'has_error':False, 'data': request.POST}
		username = request.POST.get('username')
		email = request.POST.get('email')
		password1 = request.POST.get('password')
		password2 = request.POST.get('password2')
		
		if (password_check(password1)):
			messages.error(request, 'Password Conditions below not met')
			context['has_error'] = True

		if (password1 != password2):
			messages.error(request, 'Password mismatched')
			context['has_error'] = True

		elif not Student.objects.filter(student_num = username).exists():
			messages.error(request, 'You are not registered in school database')
			context['has_error'] = True

		elif not Student.objects.filter(nsfas_status='Y'):
			messages.error(request, 'You are not funded by nsfas')
			context['has_error'] = True

		if User.objects.filter(username=username).exists():
			messages.error(request, 'Username is taken, choose another one')
			context['has_error'] = True   

		if User.objects.filter(email=email).exists():
			messages.error(request, 'email is taken, choose another one')
			context['has_error'] = True
		
		if context['has_error']:
			messages.error(request, 'Registration was not successful')
			return render(request, 'register.html', context)
		
		#Creates new user(student) and save in the Author table
		stud = User.objects.create_user(username=username, email=email)
		stud.set_password(password1)
		stud.save()
		messages.success(request, 'Successfully')   
		return redirect('stud_login')  
	return render(request, "register.html",{})  

#The stud_login page
def stud_login(request):
	if request.method == 'POST':
		context={'data': request.POST}
		username = request.POST.get('username')
		password = request.POST.get('password')

		#checkes whether the student exist in the author user table
		#The method authenticate de-encrypt the password and checks whethere 
		#the password entered matches the one in the database
		stud = authenticate(request, username=username, password=password)#
		
		#Checks if the student has logged in and not  
		if stud is not None:
			#logs the student 
			login(request, stud)
			return redirect('student')
	
		messages.add_message(request, messages.ERROR, 'Incorrect Username or Password, Please enter details')
		return render(request, 'stud_login.html',context)
	return render(request, 'stud_login.html')

#Delete all cache after logout
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def logout(request):
	if request.method == 'POST':
		#Autheticate the current user and allows them to logout
		auth.logout(request) 
		messages.success(request, 'You have logged out')
		#redirect to login page
	return HttpResponseRedirect(reverse('stud_login')) 

#Retrieve current logged in student details
def student_details(username):
	#query modules for the current logged in student 
	all_module_names = Module.objects.raw("SELECT m.module_code, m.module_name "+
										"FROM module m, course c, student st, auth_user a "+
										"WHERE m.course_code = c.course_code "+
										"AND c.course_code = st.course_code "+
										"AND st.student_num = a.username "+
										"AND a.username = "+username+"")

	#query names for the current logged in student 
	loged_username = Student.objects.raw("SELECT st.student_num, CONCAT(SUBSTR(st.stud_first_name,1,1), ' ', st.stud_last_name) as fullname "+
											"FROM student st, auth_user a "+
											"WHERE st.student_num = a.username "+
											"AND a.username = "+username+"")

	#query profile for the current logged in student 
	student_profile = Student.objects.raw("SELECT * "+
											"FROM student st, auth_user a "+
											"WHERE st.student_num = a.username "+
											"AND a.username = "+username+"")

	
	#query session for the current logged in student
	Sessions_attend = Session.objects.raw("SELECT * "
										"FROM session se,  module m, course c, student s "+ 
										"WHERE se.module_code = m.module_code "+ 
										"AND m.course_code = c.course_code "+
										"AND c.course_code = s.course_code "+
										"AND s.student_num = "+ username +"")

	context = {'all_module_names':all_module_names,
			'loged_username':loged_username,
			'student_profile':student_profile, 
			'Sessions_attend':Sessions_attend}

	#return context which has all the queries made above      
	return context

@login_required(login_url='/stud_login')
def student(request): 
	context ={}

	#Retrieve the current logged in student username
	current_user = request.user 
	username = current_user.username

	#pass the current logged in student username as an argument
	#The function student_details receive the current logged in student username as an argument
	context = student_details(username)

	print(context)
	return render(request, 'student.html',context)

def stud_profile(request):
	context ={}
	
	#Retrieve the current logged in student username
	current_user = request.user 
	username = current_user.username

	print(username)
	#pass the current logged in student username as an argument
	#The function student_details receive the current logged in student username as an argument
	context = student_details(username)
	print(context)
	return render(request, 'stud_profile.html',context)

#Student Password Reset
def RequestPasswordResetEmail(request):
	if request.method == "POST":
		user_mail = request.POST.get('email')

		current_site = get_current_site(request)

		user = User.objects.filter()

		if user.exists():
			email_contents = {
				'user':user[0],
				'domain': current_site.domain,
				'uid':urlsafe_base64_encode(force_bytes(user[0].pk)),
				'token': PasswordResetTokenGenerator().make_token(user[0]),
			} 
			link = reverse('reset-user-password', kwargs={
				'uidb64': email_contents['uid'], 'token': email_contents['token']})
			
			email_subject = 'Please follow password reset instrunction'

			reset_url = 'http://'+current_site.domain+link

			send_mail(email_subject, 
					'Hi there, Please click the link below to rest your password \n'+ reset_url, 
					'nsfastracking@gmail.com',
					[user_mail], 
					fail_silently=False)
			messages.warning(request, 'Unable to send reset link, try again later')
			return render(request,'Authenticate/reset-password.html',{})

		messages.success(request, 'We have sent you an email')
		return render(request, 'Authenticate/reset-password.html',{})
	return render(request, 'Authenticate/reset-password.html',{})


def CompletePasswordRest(request, uidb64, token):
	context = {
		'uidb64':uidb64,
		'token':token
	}
	if request.method =="POST":
		password = request.POST.get('password')
		password2 = request.POST.get('password2')

		if password != password2:
			messages.error(request, 'Passwords do not match')  
			return render(request, 'Authenticate/set-new-password.html',context)

		specialSym =['$','@','#','%','!']

		if len(password) < 6:
			messages.error(request, 'Password too low')
			return render(request, 'Authenticate/set-new-password.html',context)

		elif len(password) > 20:
			messages.error(request, 'Password exceed 20 characters')
			return render(request, 'Authenticate/set-new-password.html',context)
		
		elif not any(char.isdigit() for char in password):
			messages.error(request, 'Password does not contain a digit')
			return render(request, 'Authenticate/set-new-password.html',context)
		
		elif not any(char.isupper() for char in password):
			messages.error(request, 'Password does not have a uppercase letter')
			return render(request, 'Authenticate/set-new-password.html',context)
		
		elif not any(char.islower() for char in password):
			messages.error(request, 'Password does not have a lower letter')
			return render(request, 'Authenticate/set-new-password.html',context)
		
		elif not any(char in specialSym for char in password):
			messages.error(request, 'Password does not contain special character')
			return render(request, 'Authenticate/set-new-password.html',context)

		try:
			user_id = force_text(urlsafe_base64_decode(uidb64))
			user = User.objects.get(pk=user_id)
			#Encrypt the new user password 
			user.set_password(password)
			user.save()
			messages.success(request, 'Password reset successfuly')
			return redirect('stud_login')
		except Exception as identifier:
			
			print(identifier)
			messages.warning(request, 'Something went wrong, try again')
			return render(request, 'Authenticate/set-new-password.html',context) 
	return render(request, 'Authenticate/set-new-password.html',context)
	
	#Lecture
#Password authentication using microsoft API'S
##########################################################################
#</HomeViewSnippet>
def profile(request):
	return render(request,'profile.html',{})

def initialize_context(request):
	context = {}
	#Check for any errors in the session
	error = request.session.pop('flash_error', None)

	if error != None:
		context['errors'] = []
		context['errors'].append(error)
	
	
	#Check for user in the session
	context['user'] = request.session.get('user', {'is_authenticated': False})
	return context

#<SignInViewSnippet>
#Lecture Login using ms authentication
def sign_in(request):
	#Get the sign-in flow
	flow = get_sign_in_flow()
	#Save the expected flow so we can use it in the callback
	try:
		request.session['auth_flow'] = flow
	except Exception as e:
		print(e)
	#Redirect to the Azure sign-in page
	return HttpResponseRedirect(flow['auth_uri'])

# <SignOutViewSnippet>
def sign_out(request):
	#Clear out the user and token
	remove_user_and_token(request)
	messages.success(request, 'You have logged out')
	return HttpResponseRedirect(reverse('stud_login'))

# <CallbackViewSnippet>
def callback(request):
	#Make the token request
	result = get_token_from_code(request)
	#Get the user's profile
	user = get_user(result['access_token'])
	#Store user
	store_user(request, user)
	return HttpResponseRedirect(reverse('lecture'))


# <CalendarViewSnippet>
def lecture(request):
	context = initialize_context(request)
	user = context['user']
	email = user['email']
	username = email[0:email.find('@')]


	all_modules = Module.objects.raw("SELECT m.module_code, m.module_name "+
									"FROM course c, module m "+
									"WHERE c.course_code = m.course_code "+ 
									"AND lect_id = "+username+"")

	#query course name for the current logged in lecture 
	all_course = Course.objects.raw("SELECT c.course_code, UPPER(c.course_name) "+
										"FROM course c, module m "+
										"WHERE c.course_code = m.course_code "+
										"AND lect_id = "+ username+" "+
										"GROUP BY lect_id ")
	
	context['all_modules'] = all_modules
	context['all_course'] = all_course
  # Load the user's time zone
  # Microsoft Graph can return the user's time zone as either
  # a Windows time zone name or an IANA time zone identifier
  # Python datetime requires IANA, so convert Windows to IANA
	time_zone = get_iana_from_windows(user['timeZone'])
	tz_info = tz.gettz(time_zone)

  # Get midnight today in user's time zone
	today = datetime.now(tz_info).replace(
		hour=0,
		minute=0,
		second=0,
		microsecond=0)

  # Based on today, get the start of the week (Sunday)
	if (today.weekday() != 6):
		start = today - timedelta(days=today.isoweekday())
	else:
		start = today

	end = start + timedelta(days=7)

	token = get_token(request)

	events = get_calendar_events(
		token,
		start.isoformat(timespec='seconds'),
		end.isoformat(timespec='seconds'),
		user['timeZone'])

	if events:
	# Convert the ISO 8601 date times to a datetime object
	# This allows the Django template to format the value nicely
		for event in events['value']:
			event['start']['dateTime'] = parser.parse(event['start']['dateTime'])
			event['end']['dateTime'] = parser.parse(event['end']['dateTime'])
			code = event['subject']
			meeting = event['onlineMeeting']['joinUrl']
			start_time = event['start']['dateTime']
			end_time = event['end']['dateTime']
			print(event)
		context['events'] = events['value']
		name = user['name']
		time = datetime.now()

	#if not Session.objects.filter(sess_link=meeting).exists():
	#	email_body = 'Dear '+code+' Students\n\nGood day\n\nClass Start at: '+str(start_time)+'\nUse the following link to join the class:'+meeting+' \n\nRegards\n'+name
	#	postSession = Session(sess_organiser=name, module_code=code, sess_start=start_time, sess_end=end_time, sess_link=meeting, posted_time=time)
	#	send_mail(email_subject, 
	#					email_body,
	#					'mashengetee@gmail.com',
	#					['mashengete@live.com', '218091245@tut4life.ac.za'], 
	#					fail_silently=False)
	#	postSession.save()
	return render(request, 'lecture.html', context)
# </CalendarViewSnippet>


# <NewEventViewSnippet>
def newevent(request):
	context = initialize_context(request)
	user = context['user']
	email = user['email']
	username = email[0:email.find('@')]

	all_modules = Module.objects.raw("SELECT m.module_code, m.module_name "+
									"FROM course c, module m "+
									"WHERE c.course_code = m.course_code "+ 
									"AND lect_id = "+username+"")

	context['all_modules'] = all_modules

	if request.method == 'POST':
		if (not request.POST['ev-subject']) or \
			(not request.POST['ev-code']) or \
			(not request.POST['ev-start']) or \
			(not request.POST['ev-end']):
				context['errors'] = [
					{ 'message': 'Invalid values', 'debug': 'The subject, module_Code start, and end fields are required.'}
				]
				return render(request, 'newevent.html', context)
		attendees = None
		if request.POST['ev-attendees']:
			attendees = request.POST['ev-attendees'].split(';')
		body = request.POST['ev-body']

		# Create the event
		token = get_token(request)
		
		create_event(
			token,
			request.POST['ev-code'],
			request.POST['ev-start'],
			request.POST['ev-end'],
			attendees,
			request.POST['ev-body'],
			user['timeZone'])
		
		messages.success(request,'session created')
		return HttpResponseRedirect(reverse('lecture'))
	else:
		return render(request, 'newevent.html', context)
	print('hello')
#</NewEventViewSnippet>


#Uploading the Attendence 
def attendence(request):
	if request.method == "POST":
		file = request.FILES['document']

		data_set = file.read().decode('UTF-16')
		new_data_set = io.StringIO(data_set)
		
		count = 0
		while count <= 6:
			next(new_data_set)
			count += 1
		print(new_data_set)
		for column in csv.reader(new_data_set,delimiter='\t',quotechar="|"):
			email1=column[4]
			student_no = email1[0:email1.find('@')]

			if student_no.isdigit():
				attendence = AttendanceReg.objects.create(
					student_num = student_no,
					full_name = column[0],
					join_time = column[1],
					leave_time = column[2],
					duration = column[3],
					stud_email = email1	
				)
				attendence.save()
		messages.success(request, 'Upload was successful')
		return HttpResponseRedirect(reverse('lecture'))
	messages.error(request, 'Upload of attendace was not successful')
	return HttpResponseRedirect(reverse('lecture'))

def profile(request):
	return render(request, 'profile.html', {})

#################################################################################

#NSFAS logins
#The nsfas_login page
def nsfas_login(request):
	con = mysql.connector.connect(host="us-cdbr-east-04.cleardb.com", user = "b3d50aa8ce6f3b", passwd = "9b0a7aff", database = "heroku_1aed79e13b9d9dd")
	cursor = con.cursor()

	con2 = mysql.connector.connect(host="us-cdbr-east-04.cleardb.com", user = "b3d50aa8ce6f3b", passwd = "9b0a7aff", database = "heroku_1aed79e13b9d9dd")
	cursor2 = con2.cursor()

	sqlcommand = "select nsfas_emp_id from nsfas_empl"
	sqlcommand2 = "select n_password from nsfas_empl"

	cursor.execute(sqlcommand)
	cursor2.execute(sqlcommand2)

	emp = []
	passcode = []

	for i in cursor:
		emp.append(i)
	for x in cursor2:
		passcode.append(x)

	all_nsfas_id = list(map(itemgetter(0), emp))
	all_passcodes = list(map(itemgetter(0), passcode))

	if request.method=="POST":
		emp_id = request.POST.get("nsfas_id", "Guest (or nothing)")
		passward = request.POST.get("password", "Guest (or nothing)")
		
		k = len(emp)
		for i in range(k):
			context = {'data': request.POST}
			if all_passcodes[i]==passward and all_nsfas_id[i] == emp_id:

				return redirect('nsfas')
		messages.warning(request, 'Incorrect Username or Password, Please enter details')
		return render(request, 'nsfas_login.html',context)
	return render(request, 'nsfas_login.html')

def nsfas(request):
	stud = Student.objects.all()
	stud_login = User.objects.all()
	login_count = stud_login.count()
	all_count = stud.count()
	has_NSFAS = stud.filter(nsfas_status='Y').count()
	no_NSFAS = stud.filter(nsfas_status='N').count()
	
	context = {
		'stud': get_showing_stud(request, stud),
		'login_count':login_count,
		'all_count': all_count,
		'has_NSFAS': has_NSFAS,
		'no_NSFAS': no_NSFAS,
	}
	return render(request, 'nsfas.html', context)

def attendance_reg(request):
	attend = AttendanceReg.objects.raw("SELECT * "
										"FROM attendance_reg f, student s "+
										"WHERE f.student_num = s.student_num "+
										"AND s.nsfas_status = 'Y' "+
										"GROUP BY  f.student_num ")
	context = {
		'attend': attend,
	}
	return render(request, 'attendance.html',context)

#display student login details
def desplay_stud_login(request):
	stud_login = User.objects.all()
	all_count = stud_login.count()
   
	context = {
		'stud_login': stud_login,
		'all_count': all_count,
	}
	return render(request,'display_login_details.html', context)

def get_showing_stud(request, stud):
	if request.GET and request.GET.get('filter'): # Retrieves the data of all students tables 
		if request.GET.get('filter') == 'funded': # The fuction is passed in the display_stud_data with the filtered infomation
			return stud.filter(nsfas_status='Y')  # That information is passed and queried by the user 
		if request.GET.get('filter') == 'no_funded': #
			return stud.filter(nsfas_status='N')  #
	return stud

#Display student data
def display_stud_data(request):
	stud = Student.objects.all()
	all_count = stud.count()
	has_NSFAS = stud.filter(nsfas_status='Y').count()
	no_NSFAS = stud.filter(nsfas_status='N').count()
	context = {
		'stud': get_showing_stud(request, stud),
		'all_count': all_count,
		'has_NSFAS': has_NSFAS,
		'no_NSFAS': no_NSFAS
	}
	return render(request,'display_stud_details.html',context)

#Insert status
def Insert(request):
	if request.method == "GET":
		form = UpdateForm()
		return render(request,'insert.html', {'form':form})
	else:
		try:
			form = UpdateForm(request.POST)
			if form.is_valid():
				form.save()
			messages.success(request, 'Successful insertion of student')
			return redirect('display_stud_data')
		except:
			messages.error(request, 'failed to insert a new student')
			return render(request,'insert.html')

# Read
class BookReadView(BSModalReadView):
    model = Student
    template_name = 'read_student_data.html'

#def read_student(request, pk):
#	if request.method == 'GET':
#		stud = Student.objects.get(student_num=pk)
#		form = ReadStudForm(instance=stud)
#		context = {'form':form,
#					'data':stud }
#		return render(request,'read_student_data.html',context) 

#update status
def update(request, pk):
	stud = Student.objects.get(student_num=pk)
	form = UpdateForm(instance=stud) 
	form = UpdateForm(instance=stud)
	if request.method == 'GET':
		context={ 'stud':stud}
		return render(request, 'update.html', context)
	else:   
		try: 
			form = UpdateForm(request.POST, instance=stud) 
			if form.is_valid():
				form.save()
				messages.success(request, 'Successfully updated')
				return redirect('display_stud_data')
		except:
			messages.error(request, 'Update was not successful')
			return render(request,'update.html')

class StudReadView(BSModalReadView):
    model = User
    template_name = 'view_student.html'

#Delete login Details
def delete(request,pk):
	stud_login = AuthUser.objects.get(id=pk)
	try:
		stud_login.delete()
		messages.success(request, 'successfully deleted')
		return redirect('display_login_details')
	except:
		messages.error(request, 'The was an error trying to delete the student')
		return redirect('display_login_details')

#Exporting Students to csv, excel and pdf only those that have NSFAS Funding ###
def export_csv_Students(request):
	response = HttpResponse(content_type='text/csv')
	response['Content-Disposition'] = 'attachment; filename=Students '+ \
		str(datetime.now())+'.csv'

	#build in csv witer response
	writer = csv.writer(response)
	
	#Count number of funded students
	Total =  Student.objects.filter(nsfas_status='Y').count()

	#Write The total funded students
	writer.writerow(['Number of funded Students: ',Total])
	#Write The new line
	writer.writerow([''])
	#Write The headings 
	writer.writerow(['Student Number','Email','First Name','Last Name','Course Code',
					 'NSFAS status'])
	
	#Passing data from my attendence table into variable attendence 
	students = Student.objects.all().values_list('student_num','stud_email','stud_first_name','stud_last_name','course_code','nsfas_status').filter(nsfas_status='Y')

	#altering through the attendence and accessing each data in the database
	for stud in students:
		writer.writerow(stud)
		
	return response

def export_excel_students(request):
	response = HttpResponse(content_type='aaplication/ms-excel')
	response['Content-Disposition'] = 'attachment; filename=Students '+ \
	str(datetime.now())+'.xls'

	work_book = xlwt.Workbook(encoding='utf-8') #create a work book eg excel file
	work_sheet = work_book.add_sheet('Students') #Create and add sheet to my work book

	row_num = 0 #Add rown numbers

	font_style = xlwt.XFStyle() #Add font sytle to row 0
	
	#Count number of funded students
	Total =  Student.objects.filter(nsfas_status='Y').count()
	totalFunded = ['Number of funded Students: ', Total]
	
	for col in range(len(totalFunded)):
		work_sheet.write(row_num, col, totalFunded[col], font_style) 

	font_style.font.bold = True #Make row 3 bold
	columns = ['Student Number','Email','First Name','Last Name','Course Code','NSFAS status']
	row_num =+2 #Add 2 rows
	for col_num in range(len(columns)):
		work_sheet.write(row_num, col_num, columns[col_num], font_style) #Add row number, column, column headers and font style

	font_style = xlwt.XFStyle() #change font style from bold to normal

	rows = Student.objects.all().values_list('student_num','stud_email','stud_first_name','stud_last_name','course_code','nsfas_status').filter(nsfas_status='Y')
	for row in rows:
		row_num += 1
		for col_num in range(len(row)):
			work_sheet.write(row_num, col_num, row[col_num], font_style) #Add row number, column, column data and font style
	
	work_book.save(response)
	return response

def export_pdf(request):
	funded = Student.objects.filter(nsfas_status='Y')
	total = funded.count()
	template_path = 'pdf_file/report_pdf.html'
	context ={'funded':funded, 'total': total}
	
	#Create a Django responseobject, and specify content_type as pdf
	response = HttpResponse(content_type='application/pdf')
	response['Content-Disposition'] = 'filename= Students '+ \
	str(datetime.now())+'.pdf'

	#find the template and render it.
	template = get_template(template_path)
	html = template.render(context)

	#create a pdf
	pisa_status = pisa.CreatePDF(
		html, dest=response)
	
	#if error then show some funy view
	if pisa_status.err:
		return HttpResponse('We had some errors <pre>' + html +' </pre>')
	return response

#Exporting individual report in csv, word and pdf only those that have NSFAS Funding #

def getIndividualReport(request, pk):
	stud = AttendanceReg.objects.get(id=pk)#Code to get the student number
	print('Student number is '+str(stud))

	#QuerySet to get the number of attendance per individual student
	numOfAttend = AttendanceReg.objects.raw("SELECT count(*) AS count, id FROM (Attendance_reg AS A inner join student AS S "+
											"on S.student_num = A.student_num)"+ "WHERE A.student_num="+str(stud)+" AND nsfas_status = 'Y'")

	#QuerySet to get  the number of session related to individual student
	numOfSessionsPerStud = Session.objects.raw("SELECT sess_id, count(*) AS numOfSessions "+
									"FROM (((module AS MO inner join course AS CO on CO.course_code = MO.course_code) "+
									"inner join session SE on MO.module_code = SE.module_code) "+
									"inner join student AS ST on ST.course_code = CO.course_code) "+
									"WHERE student_num = "+str(stud)+"")
	#Quering student data for the individual report
	studentInfo = Student.objects.raw("SELECT * FROM student WHERE student_num = "+str(stud)+"")

	#Loop to get the student information to disploy on the individual report
	for studInfo in studentInfo:
		stud_fname = studInfo.stud_first_name
		stud_lname = studInfo.stud_last_name
		stud_email = studInfo.stud_email

	individual_attendance = AttendanceReg.objects.raw("SELECT * FROM attendance_reg WHERE student_num ="+str(stud)+"")
		

	#Loop to get the total number of attended sessions
	for na in numOfAttend:
		attd = na.count #variable to store the number

	#Loop to get the total number of sessions uploaded
	for ns in numOfSessionsPerStud:
		sess = ns.numOfSessions #variable to store number of uploded sessions

	attendancePercentage = (int(attd)/int(sess))*100 #Getting the attendance percentage of an individual student

	funded = AttendanceReg.objects.all()
	template_path = 'pdf_file/StudReport.html'
	time = str(datetime.now())
	context ={'funded':funded, 'time': time, 'attendancePercentage': attendancePercentage,
				'stud':stud, 'stud_fname': stud_fname, 'stud_lname':stud_lname, 'stud_email':stud_email, 'individual_attendance':individual_attendance}

				#"e_code = "+code_variable+"")

	#Create a Django responseobject, and specify content_type as pdf
	response = HttpResponse(content_type='application/pdf')
	response['Content-Disposition'] = 'filename= '+str(stud)+'-'+'Attendance '+ \
	str(datetime.now())+'.pdf'

	#find the template and render it.
	template = get_template(template_path)
	html = template.render(context)

	#create a pdf
	pisa_status = pisa.CreatePDF(
		html, dest=response)

	#if error then show some funy view
	if pisa_status.err:
		return HttpResponse('We had some errors <pre>' + html +' </pre>')

	return response

def IndReport_CSV(request, pk):
	stud = AttendanceReg.objects.get(id=pk)#Code to get the student number

	#QuerySet to get the number of attendance per individual student
	numOfAttend = AttendanceReg.objects.raw("SELECT count(*) AS count, id FROM (Attendance_reg AS A inner join student AS S "+
											"on S.student_num = A.student_num)"+ "WHERE A.student_num="+str(stud)+" AND nsfas_status = 'Y'")

	#QuerySet to get  the number of session related to individual student
	numOfSessionsPerStud = Session.objects.raw("SELECT sess_id, count(*) AS numOfSessions "+
									"FROM (((module AS MO inner join course AS CO on CO.course_code = MO.course_code) "+
									"inner join session SE on MO.module_code = SE.module_code) "+
									"inner join student AS ST on ST.course_code = CO.course_code) "+
									"WHERE student_num = "+str(stud)+"")

	#Queryset of student table							
	getStudent = Student.objects.raw("SELECT * FROM student WHERE student_num = "+str(stud)+"")

	#getting values from student table fields
	for std in 	getStudent:
		get_name = std.stud_first_name
		get_surname = std.stud_last_name

	#Loop to get the total number of attended sessions
	for na in numOfAttend:
		attd = na.count #variable to store the number

	#Loop to get the total number of sessions uploaded
	for ns in numOfSessionsPerStud:
		sess = ns.numOfSessions #variable to store number of uploded sessions

	attendancePercentage = round((int(attd)/int(sess))*100,1) #Getting the attendance percentage of an individual student

	
	response = HttpResponse(content_type='text/csv')
	response['Content-Disposition'] = 'attachment; filename='+str(stud)+'-'+str(get_name)+'-'+str(get_surname)+'-'+'Attendance '+ \
		str(datetime.now())+'.csv'

	#build in csv witer response
	writer = csv.writer(response)

	#Including attendance avearage row
	writer.writerow(['Attendance Average: '+str(attendancePercentage)+'%'])

	#Inserting empty row between attendance average and attendance headings to create space in between 
	writer.writerow([''])

	#Write The headings 
	writer.writerow(['Student Number','Full Name','Join Time','Leave Time',
					 'Duration','Email'])
	
	#Passing data from my attendence table into variable attendence 
	attendence = AttendanceReg.objects.raw("SELECT * FROM attendance_reg WHERE student_num = "+str(stud)+"")
	   
	#altering through the attendence and accessing each data in the database
	for attend in attendence:
		rows = (attend.student_num, attend.full_name, attend.join_time, attend.leave_time, attend.duration, attend.stud_email)
		writer.writerow(rows)

	return response

def IndReport_EXCEL(request, pk):
	stud = AttendanceReg.objects.get(id=pk)#Code to get the student number

	#QuerySet to get the number of attendance per individual student
	numOfAttend = AttendanceReg.objects.raw("SELECT count(*) AS count, id FROM (Attendance_reg AS A inner join student AS S "+
											"on S.student_num = A.student_num)"+ "WHERE A.student_num="+str(stud)+" AND nsfas_status = 'Y'")

	#QuerySet to get  the number of session related to individual student
	numOfSessionsPerStud = Session.objects.raw("SELECT sess_id, count(*) AS numOfSessions "+
									"FROM (((module AS MO inner join course AS CO on CO.course_code = MO.course_code) "+
									"inner join session SE on MO.module_code = SE.module_code) "+
									"inner join student AS ST on ST.course_code = CO.course_code) "+
									"WHERE student_num = "+str(stud)+"")

	#Queryset of student table							
	getStudent = Student.objects.raw("SELECT * FROM student WHERE student_num = "+str(stud)+"")

	#getting values from student table fields
	for std in 	getStudent:
		get_name = std.stud_first_name
		get_surname = std.stud_last_name

	#Loop to get the total number of attended sessions
	for na in numOfAttend:
		attd = na.count #variable to store the number

	#Loop to get the total number of sessions uploaded
	for ns in numOfSessionsPerStud:
		sess = ns.numOfSessions #variable to store number of uploded sessions

	attendancePercentage = round((int(attd)/int(sess))*100,1) #Getting the attendance percentage of an individual student

	response = HttpResponse(content_type='aaplication/ms-excel')
	response['Content-Disposition'] = 'attachment; filename='+str(stud)+'-'+str(get_name)+'-'+str(get_surname)+'-'+'Attendance '+ \
		str(datetime.now())+'.xls'

	
	work_book = xlwt.Workbook(encoding='utf-8') #create a work book eg excel file
	work_sheet = work_book.add_sheet('Attendance') #Create and add sheet to my work book
	
	row_num = 0 #Add rown numbers

	font_style = xlwt.XFStyle() #Add font sytle to row 0
	
	#Including attendance avearage row
	totalFunded = ['Attendance Average: '+str(attendancePercentage)+'%']
	
	for col in range(len(totalFunded)):
		work_sheet.write(row_num, col, totalFunded[col], font_style) 
	
	font_style.font.bold = True #Make row 3 bold
	columns = ['Student Number','Full Name','Join Time','Leave Time','Duration','Email']
	row_num =+2 #Add 2 rows
	for col_num in range(len(columns)):
		work_sheet.write(row_num, col_num, columns[col_num], font_style) #Add row number, column, column headers and font style
	font_style = xlwt.XFStyle() #change font style from bold to normal
	
	#Passing data from my attendence table into variable attendence 
	rows = AttendanceReg.objects.all().values_list('student_num','full_name','join_time','leave_time','duration','stud_email').filter(student_num=str(stud))
	#rows = (attend.student_num, attend.full_name, attend.join_time, attend.leave_time, attend.duration, attend.stud_email)
		
	#rows = AttendanceReg.objects.raw("SELECT * FROM attendance_reg WHERE student_num = "+str(stud)+"")
	#rows = AttendanceReg.objects.raw("SELECT * FROM attendance_reg WHERE student_num = "+str(stud)+"")

	for row in rows:
		row_num += 1
		for col_num in range(len(row)):		
			work_sheet.write(row_num, col_num, row[col_num], font_style) #Add row number, column, column data and font style
	
	work_book.save(response)
	return response
