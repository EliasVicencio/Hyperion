import os
import time
import psutil
from fastapi import FastAPI
from sqlalchemy import create_engine, Column, Integer, Float, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
from loguru import logger
import sys

# --- CONFIGURACIÓN DE LOGS (LOGURU) ---
logger.remove()
# Log en consola (legible)
logger.add(sys.stderr, format="{time} | {level} | {message}")
# Log en archivo (JSON estructurado para el CTO)
logger.add("logs/backend.json", rotation="10 MB", serialize=True)

# --- CONFIGURACIÓN DE BASE DE DATOS ---
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://hyperion_user:hyperion_password@db:5432/hyperion_db")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class Metric(Base):
    __tablename__ = "server_metrics"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    cpu_usage = Column(Float)
    ram_usage = Column(Float)
    disk_usage = Column(Float)

# Crear tabla
Base.metadata.create_all(bind=engine)

app = FastAPI()

@app.get("/metrics")
def get_and_save_metrics():
    # 1. Obtener métricas reales
    cpu = psutil.cpu_percent(interval=1)
    ram = psutil.virtual_memory().percent
    disk = psutil.disk_usage('/').percent

    # 2. Guardar en Base de Datos (Histórico)
    db = SessionLocal()
    new_metric = Metric(cpu_usage=cpu, ram_usage=ram, disk_usage=disk)
    db.add(new_metric)
    db.commit()
    db.refresh(new_metric)
    
    # 3. Obtener los últimos 10 registros para el gráfico
    history = db.query(Metric).order_by(Metric.timestamp.desc()).limit(10).all()
    db.close()

    data = {
        "status": "Healthy",
        "cpu_usage": cpu,
        "ram_usage": ram,
        "disk_usage": disk,
        "history": [{"cpu": m.cpu_usage, "ram": m.ram_usage, "time": m.timestamp.strftime("%H:%M:%S")} for m in reversed(history)]
    }
    
    logger.info(f"Metrics captured: CPU {cpu}%, RAM {ram}%")
    return data