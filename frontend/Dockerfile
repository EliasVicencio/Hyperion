FROM python:3.9-slim

# Usamos /app que es el estándar
WORKDIR /app

# Copiamos solo el requirements primero (para que sea más rápido)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# COPIAMOS TODO lo de la carpeta frontend al contenedor
COPY . .

# Verificamos qué archivos hay dentro (esto saldrá en el log para ayudarte)
RUN ls -la

EXPOSE 8501

# Forzamos la ruta absoluta para que no se pierda
CMD ["streamlit", "run", "/app/main.py", "--server.port=8501", "--server.address=0.0.0.0"]