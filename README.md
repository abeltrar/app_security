
### Descripción

- Verificación de vulnerabilidades para NIST.
- Marcación de vulnerabilidades que ya se tienen mapeadas.
- Recuperación de logs de usabilidad de los servicios.
- Descarga de archivo de logs.
- Generación de token para uso de los servicios.
- Recuperación de sumatoria según la gravedad de lass vulnerabilidades.
- Recuperación de información de vulnerabilidades marcadas.
- Recuperación de todas las vulnerabilidades.
- Eliminación de alguna vulnerabilidad.

# Seguridad

![](https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcQIdf4B1XRsQWRuSTmVb61INDI-_Rpsu1LLUw&s)

![](https://img.shields.io/github/stars/pandao/editor.md.svg) ![](https://img.shields.io/github/forks/pandao/editor.md.svg) ![](https://img.shields.io/github/tag/pandao/editor.md.svg) ![](https://img.shields.io/github/release/pandao/editor.md.svg) ![](https://img.shields.io/github/issues/pandao/editor.md.svg) ![](https://img.shields.io/bower/v/editor.md.svg)


**Table of Contents**

[TOCM]

[TOC]

#Uso de los servicios
##consumir_informacion_servicio

Consume el servicio de la NIST https://services.nvd.nist.gov/rest/json/cves/2.0
se consume con los parámetros (Medium,Lower,High)
de esta manera https://services.nvd.nist.gov/rest/json/cves/2.0?cvssV2Severity=LOW 
se guarda en la base de datos esta información, se recorre la respuesta mediante un ciclo for para poder armar el array que toma la información necesaria para las consultas.

##obtener_vulnerabilidades

Muestra un listado de todas las vulnerabilidades que se recuperan de la NIST.

##actualizar_estado_fixeado

Envía un valor booleano a la base de datos para marcar las vulnerabilidades que se tienen mapeadas.


##eliminar_vulnerabilidades

Se recibe el id de la CVE para poder elimar vulnerabilidades deseadas, en el cuerpo se valida que no se tenga el dato vacío y el que el array sea de la siguiente manera:

{ "ids": List [ "CVE-1999-0211", "CVE-2021-5678" ] }


##get_vulnerabilidades_no_fixeadas

Se toman desde la base de datos aquellas vulnerabilidades que tienen el estado de fixeo en false.


##get_vulnerabilidades_sumarizadas_severidad

Se realiza agrupamiento de las vulnerabilidades según su nivel de complejidad.
Alto, medio, bajo y se muestra la cantidad de casos en cada grupo.



##get_token

Con esta API se genera un STR que se guarda encriptado en la base de datos y luego se desencripta de la misma para validarlo en el AUTENTICATION del bearer token.


##obtener_logs

Se crean variable de logs para el consumo de las API, se agrega middleware personalizado para crear en la un archivo txt la data del usuario que toma la información en cada uno de los métodos.


##descargar_logs

Se tiene la opción de descargar el archivo .log para seguimiento de la seguridad de la infirmación.



##get_vulnerabilidades_fixeadas

Se rescatan de la base de datos aquellas vulnerabilidades que están marcadas como true.

##Uso de token en entorno de swagger

Para la autentificación de las API es necesario pasar el str generado desde el servicio "get_token", se configura la opción "Authorize" para ingresar el token asi:
Bearer xxxxxxxxx (es decir el token.)


Se configura la vista /redoc y /swagger para visualizar la documentación del consumo de la información.

##Consideraciones del token

No se permite el uso de los servicio sin autentificación, además tiene un limite se uso por 3 horas y se expirará.

##Docker App

Se realiza la dockerización de la aplicación alojada en el repositorio, **se puede extraer con:** docker pull abeltrar/securityapp_app

**URL PUBLIC**: https://hub.docker.com/r/abeltrar/securityapp_app



##Diagrama de solución cloud

**URL**: https://ibb.co/h81FgQx


##Logs/Auditoría de uso de la API.

Se tiene servicio para validar los logs del servicio, devulve un objeto json con la dirección remota desde donde se ejcuta el servicio y los mensajes y códigos HTTP recibidos por la misma.

Servicios documentados en swagger:
- Obtener_logs
-descargar_logs

##Testing

Se puede ejecutar desde el proyecto dockerizado en donde se realizan pruebas unitarias a cada uno de los métodos para validar su código de respuesta y la información expuesta, se tiene status oK en las realizadas:
**python manage.py test**


##Integridad de código

Se crea archivo .env para guardar API de consumo inicial de la NIST, además de las KEY que se le pasan para consumo de información.

- Se crea archivo con secret key para temas de encriptado y desencriptado del token.
- El motor de base de datos es SqLite.
- Se crea modelo y migraciones en la imagen docker.









###End
