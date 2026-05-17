"""
URL configuration for secure_dock project.
"""
from django.contrib import admin
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from monitoring.views import (
    FalcoEventViewSet,
    AlertViewSet,
    LoginView,
    LogoutView,
    RegisterView,
    CurrentUserView,
    container_list,
    container_detail,
    dashboard,
    logs_view,
)

router = DefaultRouter()
router.register(r'events', FalcoEventViewSet, basename='events')
router.register(r'alerts', AlertViewSet, basename='alerts')

urlpatterns = [
    path('admin/', admin.site.urls),

    # Auth
    path('api/auth/login/', LoginView.as_view(), name='login'),
    path('api/auth/logout/', LogoutView.as_view(), name='logout'),
    path('api/auth/register/', RegisterView.as_view(), name='register'),
    path('api/auth/me/', CurrentUserView.as_view(), name='current-user'),

    # Dashboard
    path('api/dashboard/', dashboard, name='dashboard'),

    # Containers
    path('api/containers/', container_list, name='container-list'),
    path('api/containers/<str:container_id>/', container_detail, name='container-detail'),

    # Logs
    path('api/logs/', logs_view, name='logs'),

    # Router-based (events, alerts)
    path('api/', include(router.urls)),
]
