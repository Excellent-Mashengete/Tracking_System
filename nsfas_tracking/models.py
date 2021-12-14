# This is an auto-generated Django model module.
# You'll have to do the following manually to clean this up:
#   * Rearrange models' order
#   * Make sure each model has one field with primary_key=True
#   * Make sure each ForeignKey and OneToOneField has `on_delete` set to the desired behavior
#   * Remove `managed = False` lines if you wish to allow Django to create, modify, and delete the table
# Feel free to rename the models, but don't rename db_table values or field names.
from django.db import models


class AttendanceReg(models.Model):
    id = models.AutoField(primary_key=True)
    student_num = models.CharField(max_length=9)
    full_name = models.CharField(max_length=40)
    join_time = models.CharField(max_length=45)
    leave_time = models.CharField(max_length=45)
    duration = models.CharField(max_length=45)
    stud_email = models.CharField(max_length=45)
    def __str__(self):
        return self.student_num

    class Meta:
        managed = False
        db_table = 'attendance_reg'


class AuthUser(models.Model):
    password = models.CharField(max_length=128)
    last_login = models.DateTimeField(blank=True, null=True)
    is_superuser = models.IntegerField()
    username = models.CharField(unique=True, max_length=150)
    first_name = models.CharField(max_length=150)
    last_name = models.CharField(max_length=150)
    email = models.CharField(max_length=254)
    is_staff = models.IntegerField()
    is_active = models.IntegerField()
    date_joined = models.DateTimeField()

    class Meta:
        managed = False
        db_table = 'auth_user'


class Course(models.Model):
    course_code = models.CharField(primary_key=True, max_length=15)
    course_name = models.CharField(unique=True, max_length=45)

    class Meta:
        managed = False
        db_table = 'course'

class Lecturer(models.Model):
    lect_id = models.IntegerField(primary_key=True)
    lect_email = models.CharField(unique=True, max_length=40)
    lect_first_name = models.CharField(max_length=45)
    lect_last_name = models.CharField(max_length=45)
    lect_job_title = models.CharField(max_length=45)
    lect_contact = models.CharField(unique=True, max_length=10)

    class Meta:
        managed = False
        db_table = 'lecturer'


class Module(models.Model):
    module_code = models.CharField(primary_key=True, max_length=7)
    module_name = models.CharField(unique=True, max_length=40)
    course_code = models.CharField(max_length=15)
    lect_id = models.IntegerField()

    class Meta:
        managed = False
        db_table = 'module'
        unique_together = (('module_code', 'course_code', 'lect_id'),)


class NsfasEmpl(models.Model):
    nsfas_emp_id = models.CharField(primary_key=True, max_length=7)
    n_email = models.CharField(unique=True, max_length=40)
    n_first_name = models.CharField(max_length=45)
    n_last_name = models.CharField(max_length=45)
    n_job_title = models.CharField(max_length=45)
    n_contact = models.CharField(max_length=10)
    n_password = models.CharField(max_length=200)

    class Meta:
        managed = False
        db_table = 'nsfas_empl'


class NsfasHasStudent(models.Model):
    student_num = models.CharField(primary_key=True, max_length=9)
    nsfas_emp_id = models.CharField(max_length=7)

    class Meta:
        managed = False
        db_table = 'nsfas_has_student'
        unique_together = (('student_num', 'nsfas_emp_id'),)


class Session(models.Model):
    sess_id = models.AutoField(primary_key=True)
    sess_organiser = models.CharField(max_length=100, blank=True, null=True)
    module_code = models.CharField(max_length=15)
    sess_start = models.DateTimeField(blank=True, null=True)
    sess_end = models.DateTimeField(blank=True, null=True)
    sess_body = models.TextField(blank=True, null=True)
    sess_link = models.CharField(max_length=500, blank=True, null=True)
    posted_time = models.DateTimeField()

    class Meta:
        managed = False
        db_table = 'session'
        unique_together = (('sess_id', 'module_code'),)


class Student(models.Model):
    student_num = models.CharField(primary_key=True, max_length=9)
    stud_email = models.CharField(unique=True, max_length=40)
    stud_first_name = models.CharField(max_length=45)
    middle_name = models.CharField(max_length=20, blank=True, null=True)
    stud_last_name = models.CharField(max_length=45)
    nsfas_status = models.CharField(max_length=1)
    course_code = models.CharField(max_length=15)
    def __str__(self):
        return self.student_num

    class Meta:
        managed = False
        db_table = 'student'
        unique_together = (('student_num', 'course_code'),)


class StudentHasModule(models.Model):
    student_num = models.CharField(primary_key=True, max_length=9)
    module_code = models.CharField(max_length=7)

    class Meta:
        managed = False
        db_table = 'student_has_module'
        unique_together = (('student_num', 'module_code'),)
