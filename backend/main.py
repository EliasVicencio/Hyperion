from fastapi import FastAPI, Depends, HTTPException
from auth.security import check_ip_blocked
import psutil 
from models import models, database
from scanner import run_hyperion_scan
import time

# Esto crea las tablas en MySQL si no existen
models.Base.metadata.create_all(bind=database.engine)

app = FastAPI(title="Hyperion API")

@app.get("/status", dependencies=[Depends(check_ip_blocked)])
def get_status():
    import psutil # Importar dentro por seguridad
    return {
        "cpu": psutil.cpu_percent(interval=None),
        "ram": psutil.virtual_memory().percent,
        "disk": psutil.disk_usage('/').percent,
        "status": "Healthy"
    }

@app.post("/panic")
def trigger_panic():
    return {"message": "Panic mode activated: All sessions revoked"}

@app.get("/scan-code")
def scan_project():
    report = run_hyperion_scan(".")
    return report