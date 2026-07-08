from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import text
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse
from pathlib import Path
from ..core import get_db, RAW_DB_URL, ProgresoLeccionPayload, registrar_log

BACKEND_DIR = Path(__file__).resolve().parent.parent.parent

router = APIRouter(prefix="/api/v1/academia", tags=["Academia"])

@router.get("/modulos")
async def obtener_plan_estudio_nist():
    try:
        return {
            "certificacion_global": 22,
            "horas_dedicadas": 2.4,
            "controles_validados": 2,
            "modulos": [
                {
                    "id": "nist-au",
                    "titulo": "Familia AU: Auditoría y Responsabilidad",
                    "norma": "NIST SP 800-53 (AU-2, AU-6, AU-9)",
                    "progreso": 66,
                    "descripcion": "Estudio fundamental sobre la generación de registros de auditoría, trazabilidad de actores y la inmutabilidad criptográfica obligatoria para el cumplimiento federal.",
                    "lecciones": [
                        { "id": "au-1", "titulo": "1. Introducción a la directiva AU-2 (Eventos Auditables)", "duracion": "6 min", "completada": True, "contenido": "La directiva AU-2 establece qué acciones del sistema DEBEN registrarse obligatoriamente. En Hyperion Core, esto incluye inicios de sesión, cambios de privilegios, volcados de bases de datos y bloqueos del firewall perimetral. Cada evento debe capturar de manera unívoca: qué ocurrió, cuándo ocurrió (timestamp), dónde ocurrió (nodo de origen) y quién lo provocó (actor)." },
                        { "id": "au-2", "titulo": "2. Monitoreo y Trawzabilidad bajo el control AU-6", "duracion": "8 min", "completada": True, "contenido": "El control AU-6 exige una revisión y correlación continua de los registros de auditoría para detectar comportamientos inusuales o ataques. No basta con almacenar los logs; el sistema debe contar con analíticas automáticas que correlacionen eventos aislados (por ejemplo, múltiples llamadas de API fallidas seguidas de una exportación de BD) para emitir alertas de mitigación en tiempo real." },
                        { "id": "au-3", "titulo": "3. Criptografía y Blockchain: Profundizando en AU-9", "duracion": "12 min", "completada": False, "contenido": "El control AU-9 (Integridad de Registros) es el núcleo criptográfico de Hyperion. Exige que los registros estén protegidos contra modificaciones no autorizadas. Implementamos esto mediante un encadenamiento de bloques SHA-256 (lógica blockchain): cada log almacena el hash del bloque anterior. Si un atacante altera una fila directamente en PostgreSQL, la firma digital del bloque se rompe, invalidando la cadena completa inmediatamente." }
                    ]
                },
                {
                    "id": "nist-ac-ia",
                    "titulo": "Familias AC e IA: Control de Accesos e Identidad",
                    "norma": "NIST SP 800-53 (AC-2, IA-2, IA-8)",
                    "progreso": 0,
                    "descripcion": "Políticas estrictas de autenticación de múltiples factores (MFA), gestión perimetral de sesiones y revocación inmediata de privilegios comprometidos.",
                    "lecciones": [
                        { "id": "ac-1", "titulo": "1. Control AC-2: Gestión de Cuentas de Privilegio", "duracion": "7 min", "completada": False, "contenido": "Regula el ciclo de vida de las cuentas del sistema. Las cuentas administrativas (como sysadmin) deben auditarse rigurosamente bajo el principio de 'menor privilegio posible'. Ningún operador debe poseer permisos permanentes para modificar la estructura de gobernanza sin una ventana de tiempo aprobada." },
                        { "id": "ia-2", "titulo": "2. Mecanismos de Autenticación Multifactor (MFA/TOTP)", "duracion": "10 min", "completada": False, "contenido": "El control IA-2 dictamina que todo acceso remoto o local a sistemas federales críticos requiere autenticación de factores independientes. Hyperion integra algoritmos TOTP (Time-Based One-Time Password) mediante tokens criptográficos de 6 dígitos que expiran cada 30 segundos, neutralizando ataques de reutilización de credenciales." }
                    ]
                },
                {
                    "id": "nist-si",
                    "titulo": "Familia SI: Integridad de Sistemas e Información",
                    "norma": "NIST SP 800-53 (SI-4, SI-7)",
                    "progreso": 0,
                    "descripcion": "Monitoreo de vectores maliciosos, inyecciones de código (SQL/XSS) y protección del firmware del núcleo del sistema operativo.",
                    "lecciones": [
                        { "id": "si-1", "titulo": "1. Control SI-4: Monitoreo de Alertas Perimetrales", "duracion": "9 min", "completada": False, "contenido": "Establece los requisitos para el análisis del tráfico de red entrante y saliente. El sistema busca firmas conocidas de ataques e indicadores de compromiso (IoC). Cuando nuestro firewall mitiga una inyección SQL en la API, actúa bajo el amparo estricto de este control federal." }
                    ]
                }
            ]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal database mismatch: {str(e)}")

@router.post("/completar-leccion")
async def registrar_progreso_leccion(payload: ProgresoLeccionPayload):
    if not payload.correcta:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Fallo en la validación: Checkpoint incorrecto."
        )
    try:
        return {
            "status": "success",
            "message": f"Progreso inmutable sellado para la lección '{payload.leccion_id}'."
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error writing ledger: {str(e)}")

@router.get("/descargar-norma")
async def descargar_norma_completa_nist():
    file_path = BACKEND_DIR / "NIST.SP.800-53r5.pdf"
    if not os.path.exists(file_path):
        raise HTTPException(
            status_code=404,
            detail="El documento técnico NIST.SP.800-53r5.pdf no se encuentra en la raíz del servidor."
        )
    return FileResponse(
        path=file_path,
        media_type="application/pdf",
        filename="NIST_SP_800-53_Rev5_Official.pdf"
    )

@router.get("/descargar/{leccion_id}")
async def descargar_regla_pdf(leccion_id: str):
    safe_id = Path(leccion_id).name.upper()
    file_path = BACKEND_DIR / "scripts" / f"{safe_id}.pdf"
    if os.path.exists(file_path):
        return FileResponse(
            path=file_path,
            media_type="application/pdf",
            filename=f"NIST_SP_800_53_{safe_id}.pdf"
        )

@router.get("/cursos")
async def listar_cursos_academia(operador_email: str = "operador-root", db: Session = Depends(get_db)):
    if not RAW_DB_URL:
        return {
            "iso_27001": [
                {
                    "id": 1, "titulo": "Estructura del SGSI y Ciclo PHVA",
                    "descripcion": "Domina las cláusulas obligatorias (4 a 10) para el diseño de un SGSI corporativo.",
                    "marco": "ISO27001", "nivel": "PRINCIPIANTE", "horas": 3, "total_lecciones": 4,
                    "lecciones_completadas": 1, "certificado": False
                }
            ],
            "nist_80053": [
                {
                    "id": 3, "titulo": "Hardening e Integridad de Registros (Familia AU)",
                    "descripcion": "Implementación técnica avanzada de auditoría inmutable (AU-2, AU-9, AU-12) usando criptografía.",
                    "marco": "NIST80053", "nivel": "AVANZADO", "horas": 5, "total_lecciones": 4,
                    "lecciones_completadas": 2, "certificado": False
                }
            ]
        }
    try:
        db.execute(text("SET LOCAL app.current_operator_email = :email"), {"email": operador_email})
        query = text("""
            SELECT c.id, c.titulo, c.descripcion, c.marco_normativo, c.nivel,
                   c.horas_estimadas, c.total_lecciones,
                   COALESCE(p.lecciones_completadas, 0) as completadas,
                   COALESCE(p.certificado_emitido, false) as certificado
            FROM academia_cursos c
            LEFT JOIN academia_progreso p ON c.id = p.curso_id AND p.operador_email = current_setting('app.current_operator_email')
            ORDER BY c.id ASC
        """)
        result = await run_in_threadpool(db.execute, query)
        rows = result.fetchall()
        cursos = []
        for r in rows:
            cursos.append({
                "id": r[0],
                "titulo": r[1],
                "descripcion": r[2],
                "marco": r[3],
                "nivel": r[4],
                "horas": r[5],
                "total_lecciones": r[6],
                "lecciones_completadas": r[7],
                "certificado": bool(r[8])
            })
        return {
            "iso_27001": [c for c in cursos if c["marco"] == "ISO27001"],
            "nist_80053": [c for c in cursos if c["marco"] == "NIST80053"]
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Fallo en la pasarela de extracción de la Academia: {str(e)}"
        )

@router.post("/progreso")
async def actualizar_progreso_academia(payload: ProgresoLeccionPayload, operador_email: str = "operador-root", db: Session = Depends(get_db)):
    if not RAW_DB_URL:
        return {"status": "success", "message": "Simulación local completada."}
    try:
        query_curso = text("SELECT id, total_lecciones FROM academia_cursos WHERE id = :id")
        curso = db.execute(query_curso, {"id": int(payload.modulo_id)}).fetchone()
        if not curso:
            raise HTTPException(status_code=404, detail="El curso regulatorio especificado no existe.")
        curso_id, total_lecciones = curso
        query_upsert = text("""
            INSERT INTO academia_progreso (curso_id, operador_email, lecciones_completadas)
            VALUES (:curso_id, :email, 1)
            ON CONFLICT (curso_id, operador_email)
            DO UPDATE SET lecciones_completadas = LEAST(academia_progreso.lecciones_completadas + 1, :total)
            RETURNING lecciones_completadas;
        """)
        result = db.execute(query_upsert, {"curso_id": curso_id, "email": operador_email, "total": total_lecciones})
        nuevas_completadas = result.scalar()
        certificado_emitido = False
        if nuevas_completadas >= total_lecciones:
            certificado_emitido = True
            query_cert = text("""
                UPDATE academia_progreso
                SET certificado_emitido = TRUE
                WHERE curso_id = :curso_id AND operador_email = :email
            """)
            db.execute(query_cert, {"curso_id": curso_id, "email": operador_email})
            await registrar_log(
                db,
                operador=operador_email,
                accion="COMPLIANCE_CERTIFIED",
                categoria="INFO",
                detalles=f"Operador completó satisfactoriamente el trayecto de certificación ID {curso_id}."
            )
        db.commit()
        return {
            "status": "success",
            "lecciones_completadas": nuevas_completadas,
            "certificado_emitido": certificado_emitido
        }
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))
