from django.test import TestCase, Client
from django.urls import reverse
from django.utils import timezone
from .models import Vulnerabilidad, Token
import json
from .utils import generate_token, encrypt_token,decrypt_token


class ViewsTestCase(TestCase):
    def setUp(self):
        self.client = Client()
        
        # Crear una vulnerabilidad para las pruebas
        Vulnerabilidad.objects.create(
            id_cve="CVE-1234",
            fecha_publicacion=timezone.now(),
            ultima_modificacion=timezone.now(),
            descripcion="Test vulnerability",
            nivel_complejidad="MEDIUM",
            fecha_creacion=timezone.now(),
            fecha_actualizacion=timezone.now()
        )
        
        # Obtener un token válido
        self.token = self.get_valid_token()

        # Establecer el encabezado de autorización para todas las solicitudes
        self.client.defaults['HTTP_AUTHORIZATION'] = f'Bearer {self.token}'

        self.vulnerabilidad_url = reverse('obtener_vulnerabilidades')
        self.actualizar_estado_url = reverse('actualizar_estado_fixeado')
        self.get_vulnerabilidades_no_fixeadas_url = reverse('get_vulnerabilidades_no_fixeadas')
        self.get_vulnerabilidades_sumarizadas_severidad_url = reverse('get_vulnerabilidades_sumarizadas_severidad')
        self.get_token_url = reverse('get_token')

    def get_valid_token(self):
        # Solicitar un token y devolverlo
        response = self.client.get(reverse('get_token'))
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        return data.get('token')

    def test_consumir_informacion_servicio(self):
        response = self.client.get('/consumir_informacion_servicio/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Datos procesados y almacenados en la base de datos", response.content)

    def test_obtener_vulnerabilidades(self):
        response = self.client.get(self.vulnerabilidad_url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'id_cve')
        self.assertContains(response, 'descripcion')

    def test_actualizar_estado_fixeado(self):
        payload = {'ids': ['CVE-1234']}
        response = self.client.post(self.actualizar_estado_url, json.dumps(payload), content_type='application/json')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(json.loads(response.content)['updated_count'], 1)

    def test_get_vulnerabilidades_no_fixeadas(self):
        response = self.client.get(self.get_vulnerabilidades_no_fixeadas_url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'id_cve')

    def test_get_vulnerabilidades_sumarizadas_severidad(self):
        response = self.client.get(self.get_vulnerabilidades_sumarizadas_severidad_url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'nivel_complejidad')

    def test_get_token(self):
        response = self.client.get(self.get_token_url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'token')


