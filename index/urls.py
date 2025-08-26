from django.urls import path
from . import views

urlpatterns = [
    path('', views.home),
    path('login/', views.loginPage, name="login"),
    path('signup/', views.signUp),
    path('contact/', views.contact),
    path("activate/<uidb64>/<token>/", views.activate, name="activate"),
    path("authenticator/<uidb64>/<token>/", views.authenticator, name="authenticator"),
    path('<str:username>/', views.user_screen, name='user_screen'),
]