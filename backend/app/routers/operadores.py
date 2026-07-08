from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from fastapi.concurrency import run_in_threadpool
from datetime import datetime
from ..core import get_db, RAW_DB_URL, hash_password, NuevoOperador, registrar_log, get_current_user, require_roles

router = APIRouter(prefix="/api/v1", tags=["Operadores"])

async def _crear_operador_en_bd(payload: NuevoOperador, db: Session):
    if not RAW_DB_URL:
        raise HTTPException(status_code=500, detail="Error de configuración: La variable DATABASE_URL está vacía en Vercel.")
    if len(payload.password) < 8:
        raise HTTPException(status_code=422, detail="La contraseña debe tener al menos 8 caracteres.")
    hashed = hash_password(payload.password)
    try:
        query = text("""
            INSERT INTO usuarios (email, password, role, nombre)
            VALUES (:email, :password, :role, :nombre)
            RETURNING id, email, role, nombre, ultima_conexion
        """)
        result = await run_in_threadpool(
            db.execute,
            query,
            {
                "email": payload.email,
                "password": hashed,
                "role": payload.role,
                "nombre": payload.nombre,
            },
        )
        row = result.fetchone()
        db.commit()
        await registrar_log(db, payload.email, "OPERADOR_CREATED", "WARN", detalles=f"Alta de nueva identidad por el sistema. Rol: {payload.role}")
        return {
            "id": row[0],
            "nombre": row[3] if row[3] else "Operador Corporativo",
            "email": row[1],
            "rol": (row[2].upper() + "_ROLE") if row[2] else "OPERADOR_ROLE",
            "activo": True,
            "ultima_conexion": row[4].strftime("%Y-%m-%d %H:%M:%S") if row[4] else datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Ya existe un operador registrado con ese email.")
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Excepción en la base de datos: {str(e)}")

@router.get("/operadores")
async def get_operadores_database(db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    if not RAW_DB_URL:
        raise HTTPException(status_code=500, detail="Error de configuración: La variable DATABASE_URL está vacía en Vercel.")
    try:
        query = text('SELECT id, email, role, nombre, ultima_conexion from usuarios')
        result = await run_in_threadpool(db.execute, query)
        rows = result.fetchall()
        lista_operadores = []
        for row in rows:
            lista_operadores.append({
                "id": row[0],
                "nombre": row[3] if row[3] else "Operador Corporativo",
                "email": row[1],
                "rol": (row[2].upper() + "_ROLE") if row[2] else "OPERADOR_ROLE",
                "activo": True,
                "ultima_conexion": row[4].strftime("%Y-%m-%d %H:%M:%S") if row[4] else datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })
        return lista_operadores
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Excepción en la base de datos: {str(e)}")

@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(payload: NuevoOperador, db: Session = Depends(get_db)):
    return await _crear_operador_en_bd(payload, db)

@router.post("/operadores", status_code=status.HTTP_201_CREATED)
async def crear_operador(payload: NuevoOperador, db: Session = Depends(get_db), admin: dict = Depends(require_roles(["admin", "ADMIN_ROLE"]))):
    return await _crear_operador_en_bd(payload, db)

@router.delete("/operadores/{id}")
async def eliminar_operador(id: int, db: Session = Depends(get_db), admin: dict = Depends(require_roles(["admin", "ADMIN_ROLE"]))):
    if not RAW_DB_URL:
        raise HTTPException(status_code=500, detail="Error de configuración: La variable DATABASE_URL está vacía.")
    try:
        check_query = text("SELECT email FROM usuarios WHERE id = :id")
        user = db.execute(check_query, {"id": id}).fetchone()
        if not user:
            raise HTTPException(status_code=404, detail=f"Operador con ID {id} no encontrado en el sistema.")
        delete_query = text("DELETE FROM usuarios WHERE id = :id")
        await run_in_threadpool(db.execute, delete_query, {"id": id})
        db.commit()
        await registrar_log(db, user[0], "ACCESS_REVOKED", "CRITICAL", detalles=f"Purga de credenciales completada para el ID {id}.")
        return {
            "status": "success",
            "message": f"Acceso revocado permanentemente para el operador {user[0]}."
        }
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error en la base de datos al purgar registro: {str(e)}")
