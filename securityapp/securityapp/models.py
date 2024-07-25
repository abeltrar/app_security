# models.py
from django.db import models
from datetime import datetime, timedelta

class Vulnerabilidad(models.Model):
    id = models.AutoField(primary_key=True)
    id_cve = models.TextField()
    fecha_publicacion = models.DateTimeField()
    ultima_modificacion = models.DateTimeField()
    descripcion = models.TextField()
    nivel_complejidad = models.CharField(max_length=50)
    estado_fixeado = models.BooleanField(default=False)
    fecha_creacion = models.DateTimeField(auto_now_add=True)
    fecha_actualizacion = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"CVE ID: {self.id_cve}"


class Token(models.Model):
    token_encrypted = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    expires_at = models.DateTimeField()

    def save(self, *args, **kwargs):
        if not self.id:
            self.expires_at = datetime.now() + timedelta(hours=3)
        super().save(*args, **kwargs)