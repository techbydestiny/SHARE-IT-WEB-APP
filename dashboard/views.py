from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.sites.shortcuts import get_current_site
from .models import UserInfos, Messages
from django.contrib.auth import logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.core.mail import send_mail
from django.conf import settings
from django.urls import reverse
from urllib.parse import urlencode
from django.contrib.auth import get_user_model
from django.utils.encoding import force_str 
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth.hashers import check_password
from django.utils import timezone
from datetime import timedelta

# Create your views here.

User = get_user_model()

@login_required(login_url='/login')
def homePage(request):
       # get current domain dynamically
    current_site = get_current_site(request)
    share_link = f"http://{current_site.domain}/{request.user.username}"

    return render(request, 'home.html', {"share_link": share_link})

@login_required(login_url='/login')
def archievePage(request):
    cutoff_date = timezone.now().date() - timedelta(days=5)
    savedUserMessages = Messages.objects.filter(user=request.user.username, date__lte=cutoff_date)
    # get current domain dynamically
    current_site = get_current_site(request)
    share_link = f"http://{current_site.domain}/{request.user.username}"
    return render(request, 'archieve.html', {"savedmessages": savedUserMessages , "share_link": share_link})

@login_required(login_url='/login')
def messagesPage(request):

    cutoff_date = timezone.now().date() - timedelta(days=5)
    userMessages = Messages.objects.filter(user=request.user.username, date__gte=cutoff_date)
    # get current domain dynamically
    current_site = get_current_site(request)
    share_link = f"http://{current_site.domain}/{request.user.username}"

    return render(request, 'messages.html', {"usermessages": userMessages, "share_link": share_link})

@login_required(login_url='/login')
def settingsPage(request):
    profile, created = UserInfos.objects.get_or_create(user=request.user)
    if request.method == "POST" and request.FILES.get("profile_pic"):
        profile.profile_pic = request.FILES["profile_pic"]
        profile.save()
        return redirect('/dashboard/settings') 
    return render(request, 'settings.html', {"profile": profile})

@login_required(login_url='/login')
def authEmail(request):
    if request.method == "POST":
        newEmail = request.POST.get('email')
        password = request.POST.get('password')
        # Check if password is correct
        if check_password(password, request.user.password):
            # Check if email exists
            if User.objects.filter(email=newEmail).exists():
                return render(request, "auth/email.html", {"error": "Email already taken."})
            
            obj = User.objects.get(id = request.user.id)
            obj.email = newEmail
            obj.save()
        else:
            return render(request, "auth/email.html", {"error": "Password Is Incorrect."})

        return render(request, 'auth/email.html', {"message": "New Email Saved! "})
    
    return render(request, 'auth/email.html')

@login_required(login_url='/login')
def authUser(request):
    if request.method == "POST":
        newUname = request.POST.get('username')
        password = request.POST.get('password')
        # Check if password is correct
        if check_password(password, request.user.password):
            # Check if username exists
            if User.objects.filter(username=newUname).exists():
                return render(request, "auth/user.html", {"error": "Username already taken."})
            obj = User.objects.get(id = request.user.id)
            obj.username = newUname
            obj.save()
            return render(request, 'auth/user.html', {"message": "New Username Saved! "})
        else:
           return render(request, "auth/user.html", {"error": "Password Is Incorrect"})


    return render(request, 'auth/user.html')

@login_required(login_url='/login')
def authPassword(request):
    if request.method == "POST":
        newPass = request.POST.get('password')

        # Store the new password temporarily in session
        request.session['pending_password'] = newPass 

        # Create Password Change Link
        uid = urlsafe_base64_encode(force_bytes(request.user.pk))
        token = default_token_generator.make_token(request.user)

        auth_link = request.build_absolute_uri(
            reverse("authenticator", kwargs={"uidb64": uid, "token": token})
        )

        send_mail(
            subject="Authorize Password Change",
            message=f"Hi {request.user.username}, please click the link to Change your password: {auth_link}",
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[request.user.email],
        )
        obj = User.objects.get(id = request.user.id)
        obj.password = newPass
        obj.save()
        return render(request, 'auth/password.html', {"message": "Check your email to confirm password change."})

    return render(request, 'auth/password.html')

 
@login_required(login_url='/login')
def delete_message(request, message_id):
    message = get_object_or_404(Messages, id=message_id)

    message.delete()

    return redirect('messagesPage')

def signout(request):
    logout(request)
    return redirect('/login')