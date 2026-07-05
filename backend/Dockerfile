FROM python:3.11-slim

WORKDIR /app

# Añade esta línea quirúrgica justo aquí:
RUN pip install --no-cache-dir kafka-python sqlalchemy psycopg2-binary

COPY . .

CMD ["python", "worker_ingestor.py"]