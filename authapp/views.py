from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib import messages
from django.utils.html import strip_tags
from django.template.loader import render_to_string
from django.core.mail import send_mail
from django.utils.encoding import force_bytes, smart_str
from django.utils.http import urlsafe_base64_encode,urlsafe_base64_decode
from .token import account_activation_token
# Create your views here.


def home(request):
    return render(request, 'home.html')

def signup(request):
    if request.method=='POST':
        username = request.POST['username']
        email = request.POST['email']
        password = request.POST['password']
        myuser = User.objects.create_user(username = username, email = email, password = password)
        myuser.is_active = False
        myuser.save()
        token = account_activation_token.make_token(myuser)
        uidb64 = urlsafe_base64_encode(force_bytes(myuser.pk))
        activation_link = f"http://{request.get_host()}/activate/{uidb64}/{token}/"

        subject = 'Activate Your Authentication Account'
        html_message = render_to_string('account_activate.html',{'user':myuser,'activation_link':activation_link})
        plain_message = strip_tags(html_message)  # Strip HTML tags for plain text email
        from_email = 'laxmihoneyindustry@gmail.com'  # Update with your email address
        to_email = myuser.email
        send_mail(subject, plain_message, from_email, [to_email], html_message=html_message)

        messages.success(request, "User successfully created check your email to activate")
        return redirect('signin')

        
    return render (request,'signup.html')

def activate_account(request, uidb64, token):

    try:
        uid = smart_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and account_activation_token.check_token(user, token):
        # Activate the user's account
        user.is_active = True
        user.save()
        messages.success(request, "Account activation success")
        # Redirect or display a success message
    else:
      messages.error(request,"Account activation failed")
    return redirect("/")

def signin(request):
    if request.method=='POST':
        username = request.POST['username']
        password = request.POST['password']
        
        user = authenticate(username=username,password=password)
        if user is not None:
            login(request, user)
            messages.success(request,"loged in successfully")
            return render(request,'home.html', {"user":user})

        else:
            messages.error(request,"bad credantials")
            return redirect('signin')
    return render(request, 'signin.html')





def signout(request):
    logout(request)
    messages.success(request,"logged out sucessfully")
    return redirect('/')


