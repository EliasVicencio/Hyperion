FROM python:3.10-slim

WORKDIR /app

# Copiamos el requirements que está en la raíz
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiamos TODO el contenido de la carpeta backend a la raíz de /app
COPY . .

# Comando de ejecución (ahora main.py está en la raíz de /app dentro de Docker)
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "10000"]