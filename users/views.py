from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout as auth_logout
from django.contrib import messages
from django.contrib.auth.decorators import login_required, user_passes_test
from django.views.decorators.cache import never_cache
from django.http import HttpResponseRedirect
from django.urls import reverse
import re

def is_strong_password(password):
    """Check if the password meets the criteria."""
    if len(password) < 6:
        return False
    if not re.search(r'[A-Z]', password): 
        return False
    if not re.search(r'[a-z]', password): 
        return False
    if not re.search(r'[0-9]', password): 
        return False
    if not re.search(r'[@$!%*?&]', password): 
        return False
    return True


@never_cache
def signup(request):
    if request.user.is_authenticated:
        return redirect('admin_dashboard' if request.user.is_superuser else 'home')

    if request.method == 'POST':
        email = request.POST["email"]
        username = request.POST['username']
        password = request.POST['password']
        password_confirmation = request.POST["password_confirmation"]

        if not is_strong_password(password):
            messages.error(request, "Password must be strong.")
            return render(request, 'users/signup.html')

        if password != password_confirmation:
            messages.error(request, "Passwords do not match.")
            return render(request, 'users/signup.html')

        if User.objects.filter(username=username).exists():
            messages.error(request, "Username is already taken.")
            return render(request, 'users/signup.html')

        try:
            user = User.objects.create_user(username=username, email=email, password=password)
            user.save()
            messages.success(request, "Account created successfully! You can now log in.")
            return redirect('login')
        except Exception as e:
            messages.error(request, "An error occurred while creating the account.")
            return render(request, 'users/signup.html')

    return render(request, 'users/signup.html')

@never_cache
def user_login(request):
    if request.user.is_authenticated:
        return redirect('admin_dashboard' if request.user.is_superuser else 'home')

    if request.method == 'POST':
        username = request.POST.get('username', '')
        password = request.POST.get('password', '')

        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
           
            # Set the session expiration for different user types
            request.session.set_expiry(0)  # Session expires when the browser is closed
            if user.is_superuser:
                return redirect('admin_dashboard')
            else:
                return redirect('home')
        else:
            messages.error(request, "Invalid username or password.")
            return render(request, 'users/login.html', {'username': username})

    return render(request, 'users/login.html')


@login_required(login_url='login')
def home(request):
    response = render(request, 'users/home.html')
    response['Cache-Control'] = 'no-store'  # Prevent caching of this page
    response['Pragma'] = 'no-cache'  # Ensure that the page is not cached
    response['Expires'] = '0'  # Prevent the page from being stored in the cache
    return response


def logout(request):
    auth_logout(request)
    # Clear the session and set the expiry for the cookies to the past
    request.session.flush()  # This clears the session
    response = HttpResponseRedirect(reverse('login'))
    
    # Delete cookies (this ensures that old cookies are not used to load the admin dashboard)
    response.delete_cookie('sessionid')
    response.delete_cookie('csrftoken')
    messages.success(request, "You have logged out successfully!")
    
    return response

# Admin Panel Views

@login_required(login_url='login')
@user_passes_test(lambda u: u.is_superuser, login_url='login', redirect_field_name=None)
def admin_dashboard(request):
    regular_user_search_query = request.GET.get('regular_user_search', '')
    regular_users = User.objects.filter(is_superuser=False, username__icontains=regular_user_search_query)
    superusers = User.objects.filter(is_superuser=True)

    response = render(request, 'admin/admin_dashboard.html', {
        'superusers': superusers,
        'regular_users': regular_users
    })

    # Prevent caching of this page
    response['Cache-Control'] = 'no-store'  # Prevent caching of this page
    response['Pragma'] = 'no-cache'  # Ensure that the page is not cached
    response['Expires'] = '0'  # Prevent the page from being stored in the cache

    return response

@login_required(login_url='login')
@user_passes_test(lambda u: u.is_superuser, login_url='login', redirect_field_name=None)
def create_user(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')

        if not username or not email or not password:
            messages.error(request, "All fields are required.")
            return render(request, 'admin/create_user.html')

        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already exists.")
            return render(request, 'admin/create_user.html')

        if User.objects.filter(email=email).exists():
            messages.error(request, "Email already exists.")
            return render(request, 'admin/create_user.html')

        user = User.objects.create_user(username=username, email=email, password=password)
        user.save()
        messages.success(request, f"User '{username}' created successfully.")
        return redirect('admin_dashboard')

    return render(request, 'admin/create_user.html')


@login_required(login_url='login')
@user_passes_test(lambda u: u.is_superuser, login_url='login', redirect_field_name=None)
def edit_user(request, user_id):
    user = get_object_or_404(User, id=user_id)
    if request.method == 'POST':
        username = request.POST.get('username', user.username)
        email = request.POST.get('email', user.email)
        user.username = username
        user.email = email
        user.save()
        messages.success(request, f"User '{username}' updated successfully!")
        return redirect('admin_dashboard')
    
    return render(request, 'admin/edit_user.html', {'user': user})


@login_required(login_url='login')
@user_passes_test(lambda u: u.is_superuser, login_url='login', redirect_field_name=None)
def delete_user(request, user_id):
    user = get_object_or_404(User, id=user_id)
    if request.method == 'POST':
        user.delete()
        messages.success(request, "User deleted successfully!")
        return redirect('admin_dashboard')

    return render(request, 'admin/delete_user.html', {'user': user})
