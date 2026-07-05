FROM python:3.11-slim

WORKDIR /app

# 🌟 Aseguramos que fastapi y uvicorn se instalen en la imagen
RUN pip install --no-cache-dir fastapi uvicorn sqlalchemy psycopg2-binary redis bcrypt email-validator python-multipart

COPY . .

# 🚀 El comando por defecto correcto para levantar la API
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "7860"]