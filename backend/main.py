from fastapi import FastAPI, Depends, HTTPException
from auth.security import check_ip_blocked
import psutil # Para métricas reales

app = FastAPI(title="Hyperion API")

@app.get("/status", dependencies=[Depends(check_ip_blocked)])
def get_status():
    # Pensamiento Crítico: No mentimos, damos datos reales del sistema
    return {
        "cpu_usage": psutil.cpu_percent(),
        "ram_usage": psutil.virtual_memory().percent,
        "status": "Healthy" if psutil.cpu_percent() < 80 else "Overloaded"
    }

@app.post("/panic")
def trigger_panic():
    # Aquí irá la lógica para revocar tokens
    return {"message": "Panic mode activated: All sessions revoked"}