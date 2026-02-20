from fastapi import Request, HTTPException
import time
import pyotp

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

def generate_2fa_secret():
    # Crea un secreto aleatorio único
    return pyotp.random_base32()

def get_provisioning_url(username: str, secret: str):
    # Genera la URL que la App de Google Authenticator entiende
    return pyotp.totp.TOTP(secret).provisioning_uri(
        name=username, 
        issuer_name="Hyperion-System"
    )

def verify_2fa_token(secret: str, token: str):
    # Verifica si el código de 6 dígitos ingresado es válido actualmente
    totp = pyotp.TOTP(secret)
    return totp.verify(token)