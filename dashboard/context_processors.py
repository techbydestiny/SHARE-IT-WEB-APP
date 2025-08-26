from .models import UserInfos

def user_profile(request):
    if request.user.is_authenticated:
        profile = UserInfos.objects.filter(user=request.user).first()
    else:
        profile = None
    return {'profile': profile}
