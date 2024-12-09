from django.urls import path
from . import  views

urlpatterns = [
    path('home/', views.home, name='home'),
    path('signup/', views.signup, name='signup'),
    path('login/', views.user_login, name='login'),
    path('logout/', views.logout, name='logout'),
    path('', views.home, name='home'),
    path('admin_dashboard/', views.admin_dashboard, name='admin_dashboard'),
    path('edit_user/<int:user_id>/', views.edit_user, name='edit_user'),
    path('delete_user/<int:user_id>/', views.delete_user, name='delete_user'),
    path('admin/create-user/', views.create_user, name='create_user'),
    
]


