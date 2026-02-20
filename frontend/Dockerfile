FROM python:3.11-slim

WORKDIR /app

# Streamlit necesita algunas herramientas básicas
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# Instalamos solo lo necesario para el front
RUN pip install streamlit requests

COPY . .

EXPOSE 8501

# Comando para arrancar el Dashboard
CMD ["streamlit", "run", "dashboard.py", "--server.port=8501", "--server.address=0.0.0.0"]