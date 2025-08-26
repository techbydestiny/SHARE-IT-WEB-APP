from django.contrib import admin

from .models import Messages, UserInfos

# Register your models here.
admin.site.register(Messages)
admin.site.register(UserInfos)