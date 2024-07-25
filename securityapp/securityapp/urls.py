
from django.contrib import admin
from django.urls import path
from .views import *
from django.urls import re_path
from django.urls import path
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from rest_framework import permissions
from .views import (
    consumir_informacion_servicio,
    obtener_vulnerabilidades,
    actualizar_estado_fixeado,
    eliminar_vulnerabilidades,
    get_vulnerabilidades_no_fixeadas,
    get_vulnerabilidades_sumarizadas_severidad,
    get_token,
    obtener_logs,
    descargar_logs,
    get_vulnerabilidades_fixeadas
)

schema_view = get_schema_view(
    openapi.Info(
        title="Documentation security App",
        default_version='v1',
        description="Documentación de Api de gestión de vulnerabilidades",
        terms_of_service="https://www.google.com/policies/terms/",
        contact=openapi.Contact(email="angela@tuapi.local"),
        license=openapi.License(name="BSD License"),
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
)

urlpatterns = [
    path('admin/', admin.site.urls),
    path('consumir_informacion_servicio/', consumir_informacion_servicio, name='consumir_informacion_servicio'),
    path('obtener_vulnerabilidades/', obtener_vulnerabilidades, name='obtener_vulnerabilidades'),
    path('actualizar_estado_fixeado/', actualizar_estado_fixeado, name='actualizar_estado_fixeado'),
    path('get_vulnerabilidades_no_fixeadas/', get_vulnerabilidades_no_fixeadas, name='get_vulnerabilidades_no_fixeadas'),
    path('get_vulnerabilidades_sumarizadas_severidad/', get_vulnerabilidades_sumarizadas_severidad, name='get_vulnerabilidades_sumarizadas_severidad'),
    path('get_token/', get_token, name='get_token'),
    path('obtener_logs/', obtener_logs, name='obtener_logs'),
    path('descargar_logs/', descargar_logs, name='descargar_logs'),
    path('get_vulnerabilidades_fixeadas/', get_vulnerabilidades_fixeadas, name='get_vulnerabilidades_fixeadas'),
    path('eliminar_vulnerabilidades/', eliminar_vulnerabilidades, name='eliminar_vulnerabilidades'),
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),


    
]
