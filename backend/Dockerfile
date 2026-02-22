# Usa una imagen de Python oficial
FROM python:3.10-slim

# Instala dependencias del sistema para psycopg2 (necesario para Postgres)
RUN apt-get update && apt-get install -y \
    libpq-dev \
    gcc \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Crea y define el directorio de trabajo
WORKDIR /app

# Copia los archivos de requerimientos e instala
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN pip install fastapi uvicorn sqlalchemy psycopg2-binary loguru python-jose[cryptography] passlib[bcrypt] pyotp qrcode[pil] jinja2

# COPIA TODO EL CONTENIDO de la carpeta backend al contenedor
COPY . .

# EXPLICACIÓN DEL ERROR: 
# Si tu archivo se llama main.py, el comando debe decir main:app
# Si usas app.py, debe decir app:app
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]