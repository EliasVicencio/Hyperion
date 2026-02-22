import os
from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
import pyotp

# Configuración de Seguridad
SECRET_KEY = "HYPERION_ULTRA_SECRET_KEY_2026" # ¡No la compartas!
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Forzamos bcrypt para evitar el error de los 72 bytes que vimos hoy
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """
    Crea un token firmado que el usuario usará para autenticarse.
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def generate_2fa_secret():
    """Genera una clave secreta aleatoria para el usuario"""
    return pyotp.random_base32()

def verify_2fa_code(secret: str, code: str):
    """Verifica si el código de 6 dígitos que puso el usuario es correcto"""
    totp = pyotp.TOTP(secret)
    return totp.verify(code)