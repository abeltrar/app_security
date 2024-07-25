# Imagen base de Python 3.12.4 con Alpine Linux
FROM python:3.12.4-alpine3.20

ENV PYTHONUNBUFFERED=1

# Establecer el directorio de trabajo en el contenedor
WORKDIR /app

# Instalar dependencias del sistema
RUN apk update && \
    apk add --no-cache \
        gcc \
        musl-dev \
        mariadb-dev \
        python3-dev \
        libffi-dev \
        build-base \
        openssl-dev

# Copiar el archivo requirements.txt
COPY requirements.txt .
COPY . .env


# Instalar dependencias de Python
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copiar el resto de los archivos del proyecto
COPY . .


# Comando por defecto al ejecutar el contenedor
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
