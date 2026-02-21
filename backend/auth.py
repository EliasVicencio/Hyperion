from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import JWTError, jwt
import pyotp

# Configuración de seguridad
SECRET_KEY = "tu_clave_secreta_super_segura"
ALGORITHM = "HS256"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def generate_totp_secret():
    return pyotp.random_base32()

def verify_totp(secret, code):
    totp = pyotp.TOTP(secret)
    return totp.verify(code)