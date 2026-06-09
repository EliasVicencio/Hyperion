# Usamos una imagen ligera de Python oficial
FROM python:3.10-slim

# Establecemos el directorio de trabajo dentro del contenedor
WORKDIR /app

# Copiamos el archivo de requerimientos e instalamos las dependencias
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiamos todo el código del backend al contenedor
COPY . .

# Hugging Face Spaces corre por defecto en el puerto 7860 (¡Esto es obligatorio!)
EXPOSE 7860

# Comando para arrancar FastAPI apuntando al puerto de Hugging Face
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "7860"]