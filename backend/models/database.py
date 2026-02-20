from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os

# La URL de conexión usa el nombre del servicio definido en docker-compose ('db')
SQLALCHEMY_DATABASE_URL = "mysql+pymysql://root:hyperion_root_pass@db/hyperion_db"

# El motor que gestiona las conexiones
engine = create_engine(SQLALCHEMY_DATABASE_URL)

# Cada instancia de SessionLocal será una sesión de base de datos
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Clase base para crear los modelos (tablas)
Base = declarative_base()

# Función para obtener la base de datos en cada petición
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()