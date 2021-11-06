from django.shortcuts import render,redirect, get_object_or_404
from django.http import HttpResponse, JsonResponse, HttpResponseRedirect
from django.views.decorators.http import require_http_methods
from django.urls import reverse
from django.db.models.query_utils import Q
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.tokens import PasswordResetTokenGenerator, default_token_generator
from django.core.mail import send_mail, EmailMultiAlternatives
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.template.loader import render_to_string
from django.conf import settings
from .forms import GenericModelMainForm, GenericModelForeignForm, CustomUserCreationForm, PasswordResetForm, PasswordResetConfirmForm, LoginForm
from .models import GenericModelForeign, GenericModelMain
from django.views.decorators.http import require_http_methods
from django.core import serializers
import json

@login_required
def dashboard(request):
    context = {
        'active_page':'Dashboard',
    }
    return render(request, 'mainapp/dashboard.html', context)

def read_objects(request):
    context = {
        'active_page':'Read Objects',
        'form': GenericModelMainForm(),
        'all_data': GenericModelMain.objects.all(),
    }
    return render(request, 'mainapp/read_objects.html', context)

def create_object(request):
    if request.method == 'POST':
        form = GenericModelMainForm(request.POST)

        if form.is_valid():
            form.save()
            messages.success(request, 'Action succeeded.')
            return redirect('mainapp:read_objects')
        else:
            messages.error(request, 'Action failed, validate your inputs.')

def update_object(request, pk):
    if request.method == 'POST':
        instance = get_object_or_404(GenericModelMain,pk=pk)
        form = GenericModelMainForm(request.POST, instance=instance)
        if form.is_valid():
            form.save()
            messages.success(request, 'Action succeeded.')
            return redirect(request.path_info)
        else:
            messages.error(request, 'Action failed, validate your inputs.')
    
    instance = get_object_or_404(GenericModelMain,pk=pk)
    
    context = {
        'active_page':'Read Objects',
        'form': GenericModelMainForm(instance=instance),
        'instance': instance
        
    }
    return render(request, 'mainapp/update_object.html', context)

def delete_object(request, pk):
    instance = get_object_or_404(GenericModelMain,pk=pk)
    instance.delete()
    messages.success(request, 'Action succeeded.')
    return redirect('mainapp:read_objects')





def login_user(request):
    if request.user.is_authenticated:
        return redirect(reverse(settings.LOGIN_REDIRECT_URL))
    context = {}
    if request.method == 'POST':
        form = LoginForm()
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return HttpResponseRedirect(reverse(settings.LOGIN_REDIRECT_URL))
        else:
            context['form'] = form
            messages.error(request, 'Invalid login credentials.')
            return redirect('mainapp:login')
    else:
        context['form'] = LoginForm()
        context['reset_form'] = PasswordResetForm()
        context['signup_form'] = CustomUserCreationForm()
    return render(request, 'mainapp/accounts/login.html', context)


def user_create(request):
    context = {}
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        username_error = None
        if form.is_valid():
            form.save()
            messages.success(request, 'Account created successfully.')
            return HttpResponseRedirect(reverse('mainapp:login'))
        else:
            username_error = form.errors.as_data()['username']
            if username_error:
                messages.error(request, 'Action failed, username has been taken.')
                return redirect('mainapp:login')
            context['form'] = form
            messages.error(request, 'Action failed, validate your inputs.')
    else:
        context['form'] = CustomUserCreationForm()
    return redirect('mainapp:login')

def user_password_reset(request):
    context = {}
    if request.method == 'POST':
        form = PasswordResetForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            user_list = User.objects.filter(Q(email=email))
            if user_list.exists():
                user = user_list[0]
                message_context = {'protocol': 'http',
                                   'domain': request.get_host(),
                                   'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                                   'token': default_token_generator.make_token(user),
                                   'receiver_name': f"{user.first_name} {user.last_name}"}
                message_plain = render_to_string("mainapp/email/password_reset.txt", message_context)
                message_html = render_to_string("mainapp/email/password_reset.html", message_context)
                send_mail('Password Reset', message_plain, settings.DEFAULT_FROM_EMAIL, [email], html_message = message_html)
                messages.success(request, 'If your email address is registered, you will receive a reset link and ensure to check your spam folder.')
                return redirect('mainapp:login')
            else:
                messages.success(request, 'If your email address is registered, you will receive a reset link and ensure to check your spam folder.')
                return redirect('mainapp:login')
        else:
            context['form'] = form
            messages.error(request, 'Action failed, validate your inputs.')
            return redirect('mainapp:login')

def user_password_reset_confirm(request, uid, token):
    context = {'uid': uid,
               'token': token}
    if request.method == 'POST':
        form = PasswordResetConfirmForm(request.POST)
        if form.is_valid():
            decoded_uid = urlsafe_base64_decode(uid)
            user = get_object_or_404(User, pk=decoded_uid)
            new_password = form.cleaned_data['password2']
            user.set_password(new_password)
            user.save()
            messages.success(request, 'You may now log in to your account.')
            return redirect('mainapp:login')
        else:
            context['form'] = form
            messages.error(request, 'Action failed, validate your inputs.')
    else:
        context['form'] = PasswordResetConfirmForm
    decoded_uid = urlsafe_base64_decode(uid)
    user = get_object_or_404(User, pk=decoded_uid)
    context['email'] = user.email
    return render(request, 'mainapp/accounts/password_reset_confirm.html', context)

model_mapping = {}
modelform_mapping = {}

@require_http_methods(["POST"])
def ajax_create_object(request, model_string):
    if request.is_ajax:
        model_form = modelform_mapping[model_string]
        form = model_form(json.loads(request.body))
        if form.is_valid():
            form.save()
            response_data = {
                'status': 'success',
                'message': 'Action succeeded.',
                'data':[]
            }
            response = HttpResponse(
                json.dumps(response_data),
                content_type="application/json",
                status_code =200
            )
            return response
        else:
            response_data = {
                'status': 'error',
                'message': 'Action failed, validate your inputs.',
                'data':[]
            }
            response = HttpResponse(
                json.dumps(response_data),
                content_type="application/json",
            )
            response.status_code = 400
            return response
        
@require_http_methods(["GET"])
def ajax_read_objects(request, model_string):
    if request.is_ajax:
        pk = request.GET.get('pk')
        model = model_mapping[model_string]
        if pk:
            data = get_object_or_404(model, pk=pk)
        else:
            data = model.objects.all()
        response_data = {
            'status': 'success',
            'message': 'Action succeeded.',
            'data': [data]
        }
        response = HttpResponse(
            json.dumps(response_data),
            content_type="application/json",
            status_code =200
        )
        return response
 

# BAD REQUEST
def handle400(request, exception):
    return render(request, 'mainapp/400.html', status=400)

# PERMISSION DENIED
def handle403(request, exception):
    return render(request, 'mainapp/403.html', status=403)

# PAGE NOT FOUND
def handle404(request, exception):
    return render(request, 'mainapp/404.html', status=404)

# SERVER ERROR
def handle500(request):
    return render(request, 'mainapp/500.html', status=500)
