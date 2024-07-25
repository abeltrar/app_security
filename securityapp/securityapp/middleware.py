from django.http import JsonResponse
from .models import Token
from .utils import decrypt_token
from datetime import datetime
from django.utils import timezone
from django.conf import settings



class TokenAuthMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
       # Obtener la lista de rutas exentas de los settings
        exempt_urls = getattr(settings, 'EXEMPT_URLS', [])

        # Excluir las rutas que están en la lista de exentos
        if any(request.path.startswith(url) for url in exempt_urls):
            return self.get_response(request)
        
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return JsonResponse({'error': 'Token not provided'}, status=401)

        token = auth_header.split(' ')[1]
        
        try:
            # Recuperar el token encriptado de la base de datos
            token_record = Token.objects.first()
            print(f"Encrypted token from DB: {token_record}")
            
            if token_record:
                encrypted_token = token_record.token_encrypted
                print(f"Encrypted token from DB: {encrypted_token}")

                decrypted_token = decrypt_token(encrypted_token)
                print(f"Decrypted token: {decrypted_token}")
                print(f"expired_token: {token_record.expires_at}")
                print(f"Hora_actual: {timezone.now()}")

                if decrypted_token == token:
                    # Convertir expires_at a la zona horaria actual
                    expires_at = token_record.expires_at
                    current_time = timezone.now()

                    # Convertir ambas fechas a la misma zona horaria
                    expires_at_local = expires_at.astimezone(timezone.get_current_timezone())
                    print(f"Token expires at (local): {expires_at_local}")
                    print(f"Current time (local): {current_time}")

                    if expires_at_local > current_time:
                        return self.get_response(request)
                    else:
                        return JsonResponse({'error': 'Token expired'}, status=401)
                    
                else:
                    return JsonResponse({'error': 'Invalid token'}, status=401)
            else:
                return JsonResponse({'error': 'No token found'}, status=401)
        except Exception as e:
            print(f"Error decrypting token: {str(e)}")
            return JsonResponse({'error': 'Internal server error'}, status=500)



import logging

# Configura el logger
logger = logging.getLogger(__name__)

class ApiUsageLoggingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        
        # Registra información de la solicitud
        logger.info(f"API request - Path: {request.path}, Method: {request.method}, IP: {request.META.get('REMOTE_ADDR')}")
        
        # Registra información de la respuesta
        logger.info(f"API response - Status code: {response.status_code}")
        
        return response