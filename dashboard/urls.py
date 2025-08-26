from django.urls import path
from . import views

urlpatterns = [
    path('', views.homePage, name='dashboard'),
    path('archieve/', views.archievePage),
    path('messages/', views.messagesPage, name='messagesPage'),
    path('settings/', views.settingsPage),
    path('auth/email', views.authEmail),
    path('auth/user', views.authUser),
    path('auth/password', views.authPassword),
    path('logout/', views.signout ),
    path('delete/<int:message_id>/', views.delete_message, name='delete_message'),
]
