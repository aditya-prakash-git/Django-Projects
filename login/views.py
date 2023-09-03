from django.shortcuts import redirect, render
from django.http import HttpResponse
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from reg import settings
from django.core.mail import send_mail
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from . tokens import generate_token 


# Create your views here.
def home(request):
    return render(request, "login/index.html")

def signup(request):

    if request.method == "POST":
        username = request.POST["username"]
        fname = request.POST["fname"]
        lname = request.POST["lname"]
        email = request.POST["email"]
        password1 = request.POST["password1"]
        password2 = request.POST["password2"]

        if User.objects.filter(username=username):
            messages.error(request, "Username already exists")
            return redirect('home')

        if User.objects.filter(email=email):
            messages.error(request,"Email already exists!")
            return redirect('home')
        
        if len(username)>12:
            messages.error(request,"Username must be under 12 characters")

        if not username.isalnum():
            messages.error(request, "Username must be Alpha-Numeric")
            return redirect('home')

        if password1 != password2:
            messages.error(request, "Passwords do not match!")



        myuser = User.objects.create_user(username, email, password1)
        myuser.first_name = fname
        myuser.last_name = lname
        myuser.is_active = False

        myuser.save()

        messages.success(request, "Hurray! Account created successfully!")
        

        subject = "Welcome to Aditya page"
        message = "Namaste" + myuser.first_name + "! \n" + "Welcome to my page" 
        from_email = settings.EMAIL_HOST_USER
        to_list = [myuser.email]
        send_mail(subject, message, from_email, to_list, fail_silently=True)

        current_site = get_current_site(request)
        email_subject = "Confirm your email"
        message2 = render_to_string('email_confirmation.html',{
            'name': myuser.first_name,
            'domain': current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(myuser.pk)),
            'token': generate_token.make_token(myuser)
        })
        return redirect('signin')


    return render(request, "login/signup.html")

def signin(request):

    if request.method == "POST":
        username = request.POST["username"]
        password1 = request.POST["password1"]

        user = authenticate(username=username, password=password1)

        if user is not None:
            login(request, user)
            fname = user.first_name
            return render(request, "login/index.html", {'fname': fname})
        else:
            messages.error(request, "Wrong Credentials")
            return redirect('home')


    return render(request, "login/signin.html")
    
def signout(request):
    logout(request)
    messages.success(request,"Logged out.")
    return redirect('home')

def activate(request, uidb64, token):
    try:
        uid = str(urlsafe_base64_encode(uidb64))
        myuser = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        myuser = None

    if myuser is not None and generate_token.check_token(myuser, token):
        myuser.is_active = True
        myuser.save()
        login(request, myuser)
        return redirect('home')
    



