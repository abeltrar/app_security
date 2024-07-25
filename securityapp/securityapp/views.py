
import requests
import os
import logging
from dotenv import load_dotenv
from datetime import datetime
from django.shortcuts import render
from django.http import HttpResponse
from .models import Vulnerabilidad
from django.http import JsonResponse
import json
from django.db.models import Count
from .models import Token
from .utils import generate_token, encrypt_token,decrypt_token
from drf_yasg.utils import swagger_auto_schema
from rest_framework.decorators import api_view
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from rest_framework.decorators import api_view
from rest_framework.decorators import api_view





logger = logging.getLogger(__name__)


"""Función que consume la información del servicio de la API de la NIST."""

@swagger_auto_schema(
    method='get',
    operation_description="Consume información del servicio de la API de la NIST y los almacena en la base de datos.",
    responses={200: 'Datos procesados y almacenados en la base de datos', 500: 'Error interno del servidor'}
)
@api_view(['GET'])
#Función se encarga de consumir la API de la nist para ingresar la información a la base de datos, se organiza la información que se necesita con el fin de no llenar la base de datos ya que es demasiada la información de las vulnerabilidades.
def consumir_informacion_servicio(request):
    
    logger.info(f"Request received at /consumir_informacion_servicio from IP: {request.META.get('REMOTE_ADDR')}")
    
    if request.method == 'GET':
    
        # Carga las variables de entorno desde .env
        load_dotenv()

        # Obtiene la URL de la API de NASA y la clave API desde las variables de entorno
        API_KEY_LOW = os.getenv('cvssV2Severity')
        NASA_API_URL_BASE = os.getenv('url_nist')

        # Verifica si las variables de entorno están correctamente cargadas
        if API_KEY_LOW is None:
            return HttpResponse("Error: api_key_low no está configurada en .env", status=500)
        if NASA_API_URL_BASE is None:
            return HttpResponse("Error: url_NIST no está configurada en .env", status=500)

        #Concatenar URL base con parámetros
        NASA_API_URL = NASA_API_URL_BASE + API_KEY_LOW
   
    
        response = requests.get(NASA_API_URL)
        
        if(response.status_code == 200):
            data = response.json()
        else:
            logger.error(f"Failed to retrieve data from NASA API. Status code: {response.status_code}")
            data = {}
            return HttpResponse("No se encontro informacion")
        
        
        # Lista para almacenar los datos procesados
        processed_data = []
        
        # Itera sobre los datos recibidos en la clave 'vulnerabilities'
        vulnerabilities = data.get('vulnerabilities', [])
        for vulnerability in vulnerabilities[:200]:
            cve = vulnerability.get('cve', {})
            cve_id = cve.get('id', 'N/A')
            published_date = cve.get('published', 'N/A')
            lastModified = cve.get('lastModified', 'N/A')
            # Accede a descriptions y obtiene el valor
            descriptions = cve.get('descriptions', [])
            description_value = 'N/A'
            if descriptions:
                description_value = descriptions[0].get('value', 'N/A')
            # Accede a baseSeverity
            metrics = cve.get('metrics', {})
            cvss_metrics = metrics.get('cvssMetricV2', [])
            base_severity = 'N/A'
            if cvss_metrics:
                base_severity = cvss_metrics[0].get('baseSeverity', 'N/A')
            

            # Crear o actualizar el registro en la base de datos
            Vulnerabilidad.objects.update_or_create(
                id_cve=cve_id,
                defaults={
                'fecha_publicacion': published_date,
                    'ultima_modificacion':lastModified,
                    'descripcion' : description_value,
                    'nivel_complejidad': base_severity,
                    'fecha_creacion': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'fecha_actualizacion': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
            )
        
        #Devuelve un mensaje de exito
        logger.info("Data successfully retrieved from NIST API.")
        return HttpResponse("Datos procesados y almacenados en la base de datos")
    else:
        logger.error(f"Failed to method permit. Status code: {response.status_code}")
        return JsonResponse({'error': 'Método no permitido'}, status=405)

@swagger_auto_schema(
    method='get',
    operation_description="Obtiene todas las vulnerabilidades almacenadas en la base de datos.",
    responses={200: 'Lista de vulnerabilidades', 405: 'Método no permitido'}
)
@api_view(['GET'])
def obtener_vulnerabilidades(request):
    logger.info(f"Request received at /obtener_vulnerabilidades from IP: {request.META.get('REMOTE_ADDR')}")
    if request.method == 'GET':
        # Obtener todas las vulnerabilidades de la base de datos
        vulnerabilidades = Vulnerabilidad.objects.all()[:100]

        # Crear una lista de diccionarios con los datos de las vulnerabilidades
        data = list(vulnerabilidades.values(
            'id_cve', 'fecha_publicacion', 'ultima_modificacion', 'descripcion', 'nivel_complejidad', 'estado_fixeado'
        ))

        # Devolver los datos como una respuesta JSON
        logger.info("Data successfully retrieved")
        return JsonResponse({'vulnerabilidades': data}, safe=False)
    else:
        logger.error("Método no permitido")
        return JsonResponse({'error': 'Método no permitido'}, status=405)

@swagger_auto_schema(
    method='post',
    operation_description="Actualiza el estado de las vulnerabilidades, las que ya se tienen detectadas se marcan.",
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'ids': openapi.Schema(
                type=openapi.TYPE_ARRAY,
                items=openapi.Items(type=openapi.TYPE_STRING),
                example=["CVE-1999-0211", "CVE-2021-5678"]  # Ejemplo de IDs
            )
        },
        required=['ids'],
        example={
            'ids': ["CVE-1999-0211", "CVE-2021-5678"]
        },
    
    ),
    responses={
        200: openapi.Response(
            description='Contador de vulnerabilidades actualizadas',
            examples={'application/json': {'updated_count': 2}}
        ),
        400: openapi.Response(
            description='Error en el cuerpo de la solicitud',
            examples={'application/json': {'error': 'Falta la clave "ids" en el JSON'}}
        )
    }
    
    
)
@api_view(['POST'])
def actualizar_estado_fixeado(request):
    logger.info(f"Request received at /actualizar_estado_fixeado from IP: {request.META.get('REMOTE_ADDR')}")
    if request.method == 'POST':
        try:
           
            # Verificar que la solicitud tenga un cuerpo JSON válido
            if not request.body:
                return JsonResponse({'error': 'El cuerpo de la solicitud no puede estar vacío'}, status=400)
            
            # Parsear el cuerpo de la solicitud JSON
            data = json.loads(request.body)
            
            # Validar que la clave esperada 'ids' esté presente
            if 'ids' not in data:
                return JsonResponse({'error': 'Falta la clave "ids" en el JSON'}, status=400)
            
            # Obtener la lista de IDs de vulnerabilidades
            ids_cve = data.get('ids')
            
            # Validar que ids_cve sea una lista
            if not isinstance(ids_cve, list):
                return JsonResponse({'error': 'El campo "ids" debe ser una lista de IDs'}, status=400)
            
            # Validar que la lista no esté vacía
            if not ids_cve:
                return JsonResponse({'error': 'La lista de IDs no puede estar vacía'}, status=400)
            
            # Validar que ids_cve sea una lista
            if not isinstance(ids_cve, list):
                return JsonResponse({'error': 'El campo "ids" debe ser una lista de IDs'}, status=400)
            
            # Actualizar el campo estado_fixeado a 1 para las vulnerabilidades con los IDs proporcionados
            updated_count = Vulnerabilidad.objects.filter(id_cve__in=ids_cve).update(estado_fixeado=1)
            
            logger.info("Data successfully retrieved")
            return JsonResponse({'updated_count': updated_count}, status=200)
        
        except json.JSONDecodeError:
            logger.error("Error al parsear el JSON")
            return JsonResponse({'error': 'Error al parsear el JSON'}, status=400)
    else:
        logger.error("Método no permitido")
        return JsonResponse({'error': 'Método no permitido'}, status=405)
    
@swagger_auto_schema(
    method='delete',
    operation_description="Elimina las vulnerabilidades especificadas por sus IDs.",
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'ids': openapi.Schema(type=openapi.TYPE_ARRAY, items=openapi.Items(type=openapi.TYPE_STRING))
        },
        required=['ids']
    ),
    responses={200: 'Contador de vulnerabilidades eliminadas', 400: 'Error en el cuerpo de la solicitud'}
)
@api_view(['DELETE'])
def eliminar_vulnerabilidades(request):
    logger.info(f"Request received at /eliminar_vulnerabilidades from IP: {request.META.get('REMOTE_ADDR')}")
    if request.method == 'DELETE':
        try:
            # Parsear el cuerpo de la solicitud JSON
            data = json.loads(request.body)
            
            # Verificar que la solicitud tenga un cuerpo JSON válido
            if not request.body:
                return JsonResponse({'error': 'El cuerpo de la solicitud no puede estar vacío'}, status=400)
            
            # Validar que la clave esperada 'ids' esté presente
            if 'ids' not in data:
                return JsonResponse({'error': 'Falta la clave "ids" en el JSON'}, status=400)
            
            # Obtener la lista de IDs de vulnerabilidades
            ids_cve = data.get('ids')
            
            # Validar que ids_cve sea una lista
            if not isinstance(ids_cve, list):
                return JsonResponse({'error': 'El campo "ids" debe ser una lista de IDs'}, status=400)
            
            # Validar que la lista no esté vacía
            if not ids_cve:
                return JsonResponse({'error': 'La lista de IDs no puede estar vacía'}, status=400)
            
            # Eliminar los registros con los IDs proporcionados
            deleted_count, _ = Vulnerabilidad.objects.filter(id_cve__in=ids_cve).delete()
            
            logger.info("Data successfully deleted")
            return JsonResponse({'deleted_count': deleted_count}, status=200)
        
        except json.JSONDecodeError:
            logger.error("Error al parsear el JSON")
            return JsonResponse({'error': 'Error al parsear el JSON'}, status=400)
    else:
        logger.error("Método no permitido")
        return JsonResponse({'error': 'Método no permitido'}, status=405)
    
    
@swagger_auto_schema(
    method='get',
    operation_description="Obtiene las vulnerabilidades que no están fixadas.",
    responses={200: 'Lista de vulnerabilidades no fixeadas', 405: 'Método no permitido'}
)
@api_view(['GET'])
def get_vulnerabilidades_no_fixeadas(request):
     logger.info(f"Request received at /get_vulnerabilidades_no_fixeadas from IP: {request.META.get('REMOTE_ADDR')}")
     if request.method == 'GET':
        vulnerabilidades = Vulnerabilidad.objects.filter(estado_fixeado=0)[:100]
         # Crear una lista de diccionarios con los datos de las vulnerabilidades
        data = list(vulnerabilidades.values(
            'id_cve', 'fecha_publicacion', 'ultima_modificacion', 'descripcion', 'nivel_complejidad', 'estado_fixeado'
        ))
        logger.info("Data successfully retrieved")
        return JsonResponse({'vulnerabilidades': data}, safe=False)
     else:
        logger.error("Método no permitido")
        return JsonResponse({'error': 'Método no permitido'}, status=405)
    
@swagger_auto_schema(
    method='get',
    operation_description="Obtiene la cantidad de vulnerabilidades agrupadas por severidad.",
    responses={200: 'Conteo de vulnerabilidades por severidad', 405: 'Método no permitido'}
)
@api_view(['GET'])
def get_vulnerabilidades_sumarizadas_severidad(request):
    logger.info(f"Request received at /get_vulnerabilidades_sumarizadas_severidad from IP: {request.META.get('REMOTE_ADDR')}")

    if request.method == 'GET':
    
        vulnerabilidades_severidad = Vulnerabilidad.objects.values('nivel_complejidad').annotate(count=Count('id_cve'))
        # Crear una lista de diccionarios con los datos de las vulnerabilidades
        data = list(vulnerabilidades_severidad.values(
            'nivel_complejidad', 'count'
        ))
        logger.info("Data successfully retrieved")
        return JsonResponse({'conteo_vulnerabilidades': data}, safe=False)
    else:
        logger.error("Método no permitido")

        return JsonResponse({'error': 'Método no permitido'}, status=405)
    

@swagger_auto_schema(
    method='get',
    operation_description="Genera un nuevo token para autentificación de todas las API",
    responses={200: 'Token generado', 400: 'Error al generar el token'}
)
@api_view(['GET'])
def get_token(request):
    logger.info(f"Request received at /get_token from IP: {request.META.get('REMOTE_ADDR')}")

    if request.method == 'GET':
        token = generate_token()
        token_encrypted = encrypt_token(token)
        
        # Eliminar cualquier token existente en la base de datos
        Token.objects.all().delete()
        
        # Guardar el token en la base de datos
        Token.objects.create(token_encrypted=token_encrypted)

        # Recuperar el token encriptado de la base de datos
        token_record = Token.objects.first()
        
        if token_record:
            decrypted_token = decrypt_token(token_record.token_encrypted)
            logger.info("Data successfully retrieved")
            return JsonResponse({'token': decrypted_token}, status=200)
        else:
            logger.error("No se pudo generar el token")

            return JsonResponse({'error': 'No se pudo generar el token'}, status=400)

    else:
          logger.error("Método no permitido")
          return JsonResponse({'error': 'Método no permitido'}, status=405)
    
    
     
# Ruta al archivo de logs
LOG_FILE_PATH = os.path.join(os.path.dirname(__file__), 'api_usage.log')
@swagger_auto_schema(
    method='get',
    operation_description="Obtiene el contenido del archivo de logs.",
    responses={200: 'Contenido del archivo de logs', 404: 'Archivo de logs no encontrado'}
)
@api_view(['GET'])
def obtener_logs(request):
    if request.method == 'GET':
        if os.path.exists(LOG_FILE_PATH):
            with open(LOG_FILE_PATH, 'r') as file:
                log_data = file.read()
            return JsonResponse({'logs': log_data}, status=200)
        else:
            return JsonResponse({'error': 'Archivo de logs no encontrado'}, status=404)
    else:
        return JsonResponse({'error': 'Método no permitido'}, status=405)
    
@swagger_auto_schema(
    method='get',
    operation_description="Descarga el archivo de logs.",
    responses={200: 'Archivo de logs descargado', 404: 'Archivo de logs no encontrado'}
)
@api_view(['GET'])
def descargar_logs(request):
    if request.method == 'GET':
        if os.path.exists(LOG_FILE_PATH):
            with open(LOG_FILE_PATH, 'rb') as file:
                response = HttpResponse(file.read(), content_type='application/octet-stream')
                response['Content-Disposition'] = 'attachment; filename="api_usage.log"'
            return response
        else:
            return JsonResponse({'error': 'Archivo de logs no encontrado'}, status=404)
    else:
        return JsonResponse({'error': 'Método no permitido'}, status=405)
      
      


@swagger_auto_schema(
    method='get',
    operation_description="Tomas las vulnerabilidades fixeadas",
    responses={200: 'Vulnerabilidales marcadas', 404: 'No se encontraron vulnerabilidades'}
)  
@api_view(['GET'])

def get_vulnerabilidades_fixeadas(request):
    if request.method == 'GET':
        vulnerabilidades_fixeadas= Vulnerabilidad.objects.filter(estado_fixeado=1)[:100]
        if(vulnerabilidades_fixeadas):
            # Crear una lista de diccionarios con los datos de las vulnerabilidades
            data = list(vulnerabilidades_fixeadas.values(
                'id_cve', 'fecha_publicacion', 'ultima_modificacion', 'descripcion', 'nivel_complejidad', 'estado_fixeado'
            ))
            logger.info("Data successfully retrieved")
            return JsonResponse({'vulnerabilidades_fixeadas': data}, safe=False)
        else:
            logger.error("No se encontraron vulnerabilidades fixeadas")
            return JsonResponse({'error': 'No se encontraron vulnerabilidades fixeadas'}, status=404)
    else:
        logger.error("Método no permitido")

        return JsonResponse({'error': 'Método no permitido'}, status=405)
        
   