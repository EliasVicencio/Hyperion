FROM python:3.10-slim

WORKDIR /app

# Instalamos lo mínimo necesario
RUN pip install --no-cache-dir \
    fastapi \
    uvicorn \
    passlib[bcrypt] \
    pyotp \
    psutil \
    python-dotenv \
    bandit \
    python-multipart \
    "bcrypt==4.0.1"

COPY . .

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]