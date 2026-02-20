from fastapi import Request, HTTPException
import time

# Estructura: {ip: {"attempts": int, "blocked_until": float}}
failed_attempts_tracker = {}

def check_ip_blocked(request: Request):
    ip = request.client.host
    now = time.time()
    
    if ip in failed_attempts_tracker:
        data = failed_attempts_tracker[ip]
        if data["blocked_until"] > now:
            remaining = int(data["blocked_until"] - now)
            raise HTTPException(status_code=403, detail=f"IP bloqueada. Intente en {remaining}s")
        elif data["attempts"] >= 5:
            # Resetear después de que pase el tiempo de bloqueo
            failed_attempts_tracker[ip] = {"attempts": 0, "blocked_until": 0}
    return True