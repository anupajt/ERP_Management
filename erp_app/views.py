from django.contrib.auth import get_user_model
from rest_framework import generics, permissions, status, viewsets
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import RegisterSerializer, UserSerializer, UserUpdateSerializer
from .permissions import IsAdminUser, IsAdminOrManagerUser

User = get_user_model()

class RegisterView(generics.CreateAPIView):   
    queryset = User.objects.all()
    serializer_class = RegisterSerializer
    permission_classes = (permissions.IsAuthenticated, IsAdminUser)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        
       
        return Response(
            {
                "message": f"User '{serializer.instance.email}' created successfully with role '{serializer.instance.get_role_display()}'.",
                "user": UserSerializer(serializer.instance).data
            },
            status=status.HTTP_201_CREATED,
            headers=self.get_success_headers(serializer.data)
        )

class LogoutView(APIView):   
    permission_classes = (permissions.IsAuthenticated,)

    def post(self, request):
        try:
            refresh_token = request.data["refresh"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response(status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response(status=status.HTTP_400_BAD_REQUEST, data={"error": str(e)})


class UserViewSet(viewsets.ModelViewSet):
    
    serializer_class = UserSerializer
    queryset = User.objects.all().order_by('id') 

    def get_serializer_class(self):
       
        if self.action in ['update', 'partial_update']:
            
            return UserUpdateSerializer
        return UserSerializer

    def get_queryset(self):       
        user = self.request.user
        if user.is_authenticated:
            if user.role == User.Role.ADMIN:
                return User.objects.all().order_by('id') 
            elif user.role == User.Role.MANAGER:
                
                return User.objects.filter(role__in=[User.Role.MANAGER, User.Role.EMPLOYEE]).order_by('id')
        
        return User.objects.none()

    def get_permissions(self):
        
        if self.action == 'list':
            permission_classes = [permissions.IsAuthenticated, IsAdminOrManagerUser]
        elif self.action in ['retrieve']:            
            permission_classes = [permissions.IsAuthenticated]
        elif self.action in ['create', 'update', 'partial_update', 'destroy']:
            permission_classes = [permissions.IsAuthenticated, IsAdminUser] 
        else:
            permission_classes = [permissions.IsAuthenticated] 
        return [permission() for permission in permission_classes]

    def check_object_permissions(self, request, obj):
        
        super().check_object_permissions(request, obj) 

        user = request.user       
        if self.action == 'retrieve' and user.role == User.Role.MANAGER and obj.role == User.Role.ADMIN:
            self.permission_denied(
                request, message='Managers cannot view Admin profiles.'
            )
       

    def perform_destroy(self, instance):        
        if instance.role == User.Role.ADMIN:
            if User.objects.filter(role=User.Role.ADMIN, is_active=True).count() <= 1:
                 from rest_framework.exceptions import PermissionDenied
                 raise PermissionDenied("Cannot delete the last active Admin user.")
        super().perform_destroy(instance)

class ProfileView(generics.RetrieveAPIView):    
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated] 

    def get_object(self):       
        return self.request.user
    



### FRONDEND VIEWS ###

from django.shortcuts import render, redirect
from django.contrib.auth import login, logout
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from .models import User
from django.contrib.auth import authenticate
from django.contrib import messages
from django.core.cache import cache
from django.views.decorators.cache import never_cache
from django.core.paginator import Paginator


def home_view(request):
    if request.user.is_authenticated:
        if request.user.role == User.Role.ADMIN:
            return redirect('user_list')
        elif request.user.role == User.Role.MANAGER:
            return redirect('user_list')
        else:
            return redirect('profile')
    return redirect('login')

@require_http_methods(['GET', 'POST'])
def login_view(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        user = authenticate(request, username=email, password=password)
        if user is not None:
            login(request, user)            
            return redirect('home')        
    return render(request, 'login.html')

@require_http_methods(['GET', 'POST'])
def register_view(request):    
    if request.method == 'POST':
        form_data = request.POST.copy()        
       
        if not request.user.is_authenticated or request.user.role != User.Role.ADMIN:
            form_data['role'] = User.Role.EMPLOYEE

        if form_data['password1'] != form_data['password2']:
            messages.error(request, "Passwords do not match")
            return render(request, 'register.html')
            
        try:
            user = User.objects.create_user(
                email=form_data['email'],
                password=form_data['password1'],
                first_name=form_data['first_name'],
                last_name=form_data['last_name'],
                role=form_data['role']
            )
            
            if not request.user.is_authenticated or request.user.role != User.Role.ADMIN:         
                return redirect('login')                
            
            return redirect('user_list')
            
        except Exception as e:
            messages.error(request, f"Error: {str(e)}")
   
    context = {}
    if request.user.is_authenticated and request.user.role == User.Role.ADMIN:
        context['role_choices'] = User.Role.choices
    return render(request, 'register.html', context)



@login_required
def user_list_view(request):
    if request.user.role == User.Role.ADMIN:
        users = User.objects.exclude(id=request.user.id).order_by('id')
    elif request.user.role == User.Role.MANAGER:        
        users = User.objects.filter(
            role=User.Role.EMPLOYEE
        ).order_by('id')
    else:
        messages.error(request, "You don't have permission to view this page")
        return redirect('profile')
    
    
    paginator = Paginator(users, 5)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    return render(request, 'user_list.html', {'page_obj': page_obj})


@login_required
def profile_view(request):
    return render(request, 'profile.html', {'user': request.user})

@login_required
def view_user_view(request, user_id):
    try:
        user = User.objects.get(pk=user_id)
    except User.DoesNotExist:
        messages.error(request, "User not found")
        return redirect('user_list')
        
   
    if request.user.role == User.Role.EMPLOYEE:
        messages.error(request, "You don't have permission to view other users")
        return redirect('profile')
    elif request.user.role == User.Role.MANAGER and user.role == User.Role.ADMIN:
        messages.error(request, "Managers cannot view Admin profiles")
        return redirect('user_list')

    return render(request, 'profile.html', {'user': user})

@login_required
@require_http_methods(['GET', 'POST'])
def edit_user_view(request, user_id):
    if request.user.role != User.Role.ADMIN:
        messages.error(request, "Only admins can edit users")
        return redirect('profile')

    try:
        user_to_edit = User.objects.get(pk=user_id)
    except User.DoesNotExist:
        messages.error(request, "User not found")
        return redirect('user_list')

    if request.method == 'POST':
        form_data = request.POST.copy()
        
       
        required_fields = ['email', 'first_name', 'last_name']
        if any(not form_data.get(field) for field in required_fields):
            messages.error(request, "All fields are required")
            return render(request, 'edit_user.html', {'user': user_to_edit, 'role_choices': User.Role.choices})

        try:
           
            new_email = form_data['email']
            if new_email != user_to_edit.email and User.objects.filter(email=new_email).exists():
                messages.error(request, "Email address already in use by another account")
                return render(request, 'edit_user.html', {'user': user_to_edit, 'role_choices': User.Role.choices})
            
         
            new_role = form_data.get('role')
            if (user_to_edit.role == User.Role.ADMIN and 
                new_role != User.Role.ADMIN and 
                User.objects.filter(role=User.Role.ADMIN, is_active=True).count() <= 1):
                messages.error(request, "Cannot remove the last active admin")
                return render(request, 'edit_user.html', {'user': user_to_edit, 'role_choices': User.Role.choices})
            
           
            user_to_edit.email = new_email
            user_to_edit.first_name = form_data['first_name']
            user_to_edit.last_name = form_data['last_name']
            user_to_edit.role = new_role
            user_to_edit.save()
            
            
            return redirect('user_list')
            
        except Exception as e:
            messages.error(request, f"Error updating user: {str(e)}")
    
    return render(request, 'edit_user.html', {
        'user': user_to_edit,
        'role_choices': User.Role.choices
    })

@login_required
@require_http_methods(['POST'])  
def delete_user_view(request, user_id):
    if request.user.role != User.Role.ADMIN:
        messages.error(request, "Only admins can delete users")
        return redirect('profile')

    try:
        user_to_delete = User.objects.get(pk=user_id)
        
        
        if user_to_delete.role == User.Role.ADMIN:
            admin_count = User.objects.filter(role=User.Role.ADMIN, is_active=True).count()
            if admin_count <= 1:
                messages.error(request, "Cannot delete the last active admin")
                return redirect('user_list')
        
        user_to_delete.delete()        
        
    except User.DoesNotExist:
        messages.error(request, "User not found")
    
    return redirect('user_list')

def accounts_login_redirect(request):
    return redirect('login')


@never_cache
@login_required
def logout_view(request):   
    try:
        refresh_token = request.POST.get("refresh") 
        token = RefreshToken(refresh_token)
        token.blacklist()  
    except Exception as e:
        pass  
    
    logout(request)
    cache.clear()
    request.session.flush()

    response = redirect('login')
    response['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response['Pragma'] = 'no-cache'
    response['Expires'] = '0'
    return response