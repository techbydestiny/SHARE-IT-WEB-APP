from django.db import models
from django.utils import timezone
from django.contrib.auth.models import User

# Create your models here.

class Messages(models.Model):
    message = models.TextField()
    date = models.DateField(default=timezone.now)
    reported = models.BooleanField(default=False)
    user = models.CharField(max_length=150)

    def __str__(self):
        return  self.message[:50] 
    

class UserInfos(models.Model):
    date = models.DateField(default=timezone.now)
    profile_pic = models.ImageField(upload_to='profiles/', null=True, blank=True)
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="userinfo")

    def __str__(self):
        return  self.user.username