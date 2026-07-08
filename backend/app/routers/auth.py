from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from sqlalchemy import text
from fastapi.concurrency import run_in_threadpool
from ..core import (
    get_db, RAW_DB_URL, verify_password, hash_password,
    PasswordUpdateRequest, PasswordRecovery2FARequest,
    TokenVerifyRequest, Setup2FAResponse, registrar_log,
    create_access_token, get_current_user
)

router = APIRouter(prefix="/auth", tags=["Auth"])

@router.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    username = form_data.username
    password = form_data.password
    try:
        query = text('SELECT password, role, two_factor_enabled FROM usuarios WHERE email = :email')
        user_record = db.execute(query, {"email": username}).fetchone()
        if not user_record or not verify_password(password, user_record[0]):
            await registrar_log(db, username, "LOGIN_FAILED", "WARN", detalles="Intento fallido de autenticación.")
            raise HTTPException(status_code=400, detail="Credenciales incorrectas o usuario no registrado.")
        two_factor_enabled = bool(user_record[2])
        role = (user_record[1].upper() + "_ROLE") if user_record[1] else "OPERADOR_ROLE"
        if two_factor_enabled:
            return {
                "status": "requires_2fa",
                "message": "Segundo factor de autenticación requerido para este operador.",
                "username": username
            }
        access_token = create_access_token(data={"sub": username, "role": role})
        await registrar_log(db, username, "LOGIN_SUCCESS", "INFO", detalles="Inicio de sesión perimetral correcto.")
        return {
            "status": "success",
            "access_token": access_token,
            "token_type": "bearer",
            "username": username,
            "role": role
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error en el proceso de autenticación: {str(e)}")

@router.post("/verify-2fa")
async def verify_2fa(data: TokenVerifyRequest, db: Session = Depends(get_db)):
    import pyotp
    try:
        query = text('SELECT two_factor_secret, role FROM usuarios WHERE email = :email')
        user_record = db.execute(query, {"email": data.username}).fetchone()
        if not user_record or not user_record[0]:
            raise HTTPException(status_code=400, detail="Este operador no tiene configurada una clave TOTP.")
        totp = pyotp.TOTP(user_record[0])
        if not totp.verify(data.token):
            await registrar_log(db, data.username, "2FA_FAILED", "WARN", detalles="Fallo de código de verificación 2FA.")
            raise HTTPException(status_code=400, detail="Código de seguridad inválido o expirado.")
        role = (user_record[1].upper() + "_ROLE") if user_record[1] else "OPERADOR_ROLE"
        access_token = create_access_token(data={"sub": data.username, "role": role})
        await registrar_log(db, data.username, "2FA_SUCCESS", "INFO", detalles="Doble factor validado.")
        return {
            "status": "success",
            "access_token": access_token,
            "token_type": "bearer",
            "username": data.username,
            "role": role
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Fallo en verificación perimetral: {str(e)}")

@router.get("/me")
async def get_me(current_user: dict = Depends(get_current_user)):
    return current_user

@router.post("/update-password")
async def update_password(payload: PasswordUpdateRequest, db: Session = Depends(get_db)):
    if not RAW_DB_URL:
        raise HTTPException(status_code=500, detail="Error de configuración: DATABASE_URL vacía.")
    try:
        check_user_query = text("SELECT id FROM usuarios WHERE email = :email")
        user_exists = db.execute(check_user_query, {"email": payload.username}).fetchone()
        if not user_exists:
            raise HTTPException(status_code=404, detail="El operador especificado no reside en el sistema.")
        new_hashed_password = hash_password(payload.new_password)
        update_query = text("UPDATE usuarios SET password = :password WHERE email = :email")
        await run_in_threadpool(db.execute, update_query, {"password": new_hashed_password, "email": payload.username})
        db.commit()
        await registrar_log(
            db,
            operador=payload.username,
            accion="PASSWORD_CHANGED",
            categoria="WARN",
            detalles="Modificación manual exitosa de credenciales criptográficas de acceso."
        )
        return {"status": "success", "message": "Contraseña actualizada exitosamente."}
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")

@router.post("/recover-password")
async def recover_password_via_2fa(payload: PasswordRecovery2FARequest, db: Session = Depends(get_db)):
    import pyotp
    if not RAW_DB_URL:
        raise HTTPException(status_code=500, detail="DATABASE_URL no configurada.")
    try:
        query = text("SELECT two_factor_secret, two_factor_enabled FROM usuarios WHERE email = :email")
        user_record = db.execute(query, {"email": payload.username}).fetchone()
        if not user_record:
            raise HTTPException(status_code=400, detail="Verificación de identidad fallida o parámetros inválidos.")
        secret_totp = user_record[0]
        mfa_enabled = bool(user_record[1])
        if not mfa_enabled or not secret_totp:
            raise HTTPException(
                status_code=400,
                detail="Esta cuenta no cuenta con recuperación por TOTP activa. Contacte al administrador del sistema."
            )
        totp = pyotp.TOTP(secret_totp)
        if not totp.verify(payload.token):
            await registrar_log(db, payload.username, "RECOVERY_FAILED", "WARN", detalles="Código TOTP de recuperación inválido.")
            raise HTTPException(status_code=400, detail="Código de seguridad inválido o expirado.")
        new_hashed_password = hash_password(payload.new_password)
        update_query = text("UPDATE usuarios SET password = :password WHERE email = :email")
        await run_in_threadpool(db.execute, update_query, {"password": new_hashed_password, "email": payload.username})
        db.commit()
        await registrar_log(
            db,
            operador=payload.username,
            accion="PASSWORD_RECOVERED",
            categoria="WARN",
            detalles="Restablecimiento auto-servicio exitoso mediante validación token 2FA/TOTP."
        )
        return {"status": "success", "message": "Credenciales actualizadas correctamente en Hyperion Core."}
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error en pasarela de recuperación: {str(e)}")

@router.post("/setup-2fa", response_model=Setup2FAResponse)
async def setup_2fa(username: str, db: Session = Depends(get_db)):
    import pyotp
    try:
        secret = pyotp.random_base32()
        totp_auth_url = pyotp.totp.TOTP(secret).provisioning_uri(
            name=username,
            issuer_name="Hyperion Core"
        )
        query = text('UPDATE usuarios SET two_factor_secret = :secret, two_factor_enabled = FALSE WHERE email = :email')
        db.execute(query, {"secret": secret, "email": username})
        db.commit()
        return {"secret": secret, "qr_uri": totp_auth_url}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error al generar semilla TOTP: {str(e)}")

@router.post("/activate-2fa")
async def activate_2fa(data: TokenVerifyRequest, db: Session = Depends(get_db)):
    import pyotp
    try:
        query = text('SELECT two_factor_secret FROM usuarios WHERE email = :email')
        user_record = db.execute(query, {"email": data.username}).fetchone()
        if not user_record or not user_record[0]:
            raise HTTPException(status_code=400, detail="Semilla TOTP no inicializada para esta cuenta.")
        totp = pyotp.TOTP(user_record[0])
        if not totp.verify(data.token):
            raise HTTPException(status_code=400, detail="El código de confirmación no coincide con el autenticador.")
        query_update = text('UPDATE usuarios SET two_factor_enabled = TRUE WHERE email = :email')
        db.execute(query_update, {"email": data.username})
        db.commit()
        await registrar_log(db, data.username, "2FA_ACTIVATED", "INFO", detalles="El operador activó el resguardo por token TOTP.")
        return {"status": "activated", "message": "Autenticación de Dos Factores vinculada correctamente al sistema."}
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error en activación de seguridad: {str(e)}")

@router.get("/status-2fa")
async def get_2fa_status(username: str, db: Session = Depends(get_db)):
    try:
        query = text('SELECT two_factor_enabled FROM usuarios WHERE email = :email')
        user_record = db.execute(query, {"email": username}).fetchone()
        return {"two_factor_enabled": bool(user_record[0]) if user_record else False}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/deactivate-2fa")
async def deactivate_2fa(data: TokenVerifyRequest, db: Session = Depends(get_db)):
    import pyotp
    try:
        query = text('SELECT two_factor_secret FROM usuarios WHERE email = :email')
        user_record = db.execute(query, {"email": data.username}).fetchone()
        if not user_record or not user_record[0]:
            raise HTTPException(status_code=400, detail="No hay una configuración 2FA activa en este usuario.")
        totp = pyotp.TOTP(user_record[0])
        if not totp.verify(data.token):
            raise HTTPException(status_code=400, detail="Código de desactivación incorrecto.")
        query_update = text('UPDATE usuarios SET two_factor_enabled = FALSE, two_factor_secret = NULL WHERE email = :email')
        db.execute(query_update, {"email": data.username})
        db.commit()
        await registrar_log(db, data.username, "2FA_DEACTIVATED", "CRITICAL", detalles="Doble factor removido por el operador.")
        return {"status": "deactivated", "message": "Autenticación de dos factores removida."}
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))
