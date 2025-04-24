from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from rest_framework_simplejwt.tokens import RefreshToken

User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
   
    role = serializers.CharField(source='get_role_display') 

    class Meta:
        model = User
        fields = ('id', 'email', 'first_name', 'last_name', 'role', 'is_active', 'date_joined')
        read_only_fields = ('id', 'date_joined')


class RegisterSerializer(serializers.ModelSerializer):   
    password = serializers.CharField(
        write_only=True, required=True, validators=[validate_password]
    )
    password2 = serializers.CharField(write_only=True, required=True, label="Confirm password")   
    role = serializers.ChoiceField(choices=User.Role.choices, required=True)

    class Meta:
        model = User       
        fields = ('email', 'password', 'password2', 'first_name', 'last_name', 'role')
        extra_kwargs = {
            'first_name': {'required': True},
            'last_name': {'required': True},
        }

    def validate(self, attrs):       
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})
       
        return attrs

    def create(self, validated_data):
       
        validated_data.pop('password2')
        password = validated_data.pop('password')        
        user = User.objects.create_user(**validated_data)
        user.set_password(password)
        user.save()
        return user

class UserUpdateSerializer(serializers.ModelSerializer):    
    role = serializers.ChoiceField(choices=User.Role.choices, required=False)

    class Meta:
        model = User
        fields = ('email', 'first_name', 'last_name', 'role', 'is_active')
        extra_kwargs = {
            'email': {'required': False},
            'first_name': {'required': False},
            'last_name': {'required': False},
        }

    def update(self, instance, validated_data):        
        request = self.context.get('request')
        new_role = validated_data.get('role')

        if new_role and request and request.user and not request.user.is_admin:
             if new_role == User.Role.ADMIN or new_role == User.Role.MANAGER:
                 raise serializers.ValidationError({"role": "Only Admins can assign Admin or Manager roles."})            
             if request.user.is_manager and instance.is_admin:
                  raise serializers.ValidationError({"detail": "Managers cannot edit Admin users."})
        
        if instance.is_admin and new_role and new_role != User.Role.ADMIN:
             if User.objects.filter(role=User.Role.ADMIN, is_active=True).count() <= 1:
                 raise serializers.ValidationError({"role": "Cannot remove the last active Admin."})

        return super().update(instance, validated_data)