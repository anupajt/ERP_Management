from rest_framework import permissions

class IsAdminUser(permissions.BasePermission):
    
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated and request.user.role == request.user.Role.ADMIN)

class IsManagerUser(permissions.BasePermission):
    
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated and request.user.role == request.user.Role.MANAGER)

class IsEmployeeUser(permissions.BasePermission):
    
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated and request.user.role == request.user.Role.EMPLOYEE)

class IsAdminOrManagerUser(permissions.BasePermission):
   
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated and (request.user.role == request.user.Role.ADMIN or request.user.role == request.user.Role.MANAGER))

