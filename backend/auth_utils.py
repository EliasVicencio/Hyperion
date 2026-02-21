from passlib.context import CryptContext

# Añadimos 'schemes' y forzamos el uso de la implementación pura de python si es necesario
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    # Forzamos que la contraseña sea tratada como string corto
    return pwd_context.hash(password)