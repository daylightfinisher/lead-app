from django.db import models
from django.contrib.auth.models import User
import config
import os
import uuid

def get_file_path(instance, filename):
    ext = filename.split('.')[-1]
    filename = "%s.%s" % (uuid.uuid4(), ext)
    return os.path.join('uploads', filename)


class Api_Settings(models.Model):
    user                   = models.OneToOneField(User, null=True, blank=True)
    ga_profile_id          = models.CharField(max_length = 200, null = True, blank = True)
    #lead_token             = models.CharField(max_length = 200, null = True, blank = True)
    access_token           = models.CharField(max_length=500, null=True, blank=True)
    expires                = models.CharField(max_length=100, null=True, blank=True)
    refresh_token          = models.CharField(max_length=500, null=True, blank=True)
    token_type             = models.CharField(max_length=100, null=True, blank=True)
    created                = models.DateTimeField(auto_now_add=True)
    updated                = models.DateTimeField(auto_now=True)
    

class LeadApi_Settings(models.Model):
    user                   = models.OneToOneField(User, null=True, blank=True)
    lead_token             = models.CharField(max_length = 200, null = True, blank = True)
    no_of_employees        = models.BooleanField(default=False)
    region                 = models.BooleanField(default=False)
    continent              = models.BooleanField(default=False)
    country                = models.BooleanField(default=False)
    address                = models.BooleanField(default=False)
    page_title             = models.BooleanField(default=True)
    page_url               = models.BooleanField(default=True)
    revenue                = models.BooleanField(default=True)
    city                   = models.BooleanField(default=True)
    icon_image             = models.ImageField(upload_to='pic_folder/',blank=True, null=True)
    #icon_file              = models.FileField(upload_to='media/uploads/%Y/%m/%d/%H/%M/%S/')
    bg_color               = models.CharField(max_length=100, null=True, blank=True)
    