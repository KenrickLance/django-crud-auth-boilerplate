from django.urls import path, include
from django.contrib.auth import views as auth_views
from django.urls import reverse
from django.conf.urls import handler404

from . import views

app_name = 'mainapp'

urlpatterns = [
    path('dashboard', views.dashboard, name='dashboard'),
    path('login', views.login_user, name='login'),
    path('logout', auth_views.LogoutView.as_view(), name='logout'),
    path('user_create', views.user_create, name='user_create'),

    path('password_reset/', views.user_password_reset, name='password_reset'),
    path('password_reset/confirm/<uid>/<token>/', views.user_password_reset_confirm, name='password_reset_confirm'),

    path('create_object',views.create_object,name='create_object'),
    path('update_object/<str:pk>',views.update_object,name='update_object'),
    path('delete_object/<str:pk>',views.delete_object,name='delete_object'),
    path('read_objects',views.read_objects,name='read_objects'),

    path('ajax_create_object/<str:model_string>', views.ajax_create_object, name='ajax_create_object'),
    path('ajax_read_objects/<str:model_string>', views.ajax_read_objects, name='ajax_read_objects')
]