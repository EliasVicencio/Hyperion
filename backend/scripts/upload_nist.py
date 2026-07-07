import os
import uuid
import re
from supabase import create_client, Client
from pypdf import PdfReader

# Intentar cargar variables desde un archivo .env si python-dotenv está instalado
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# 1. Configuración de Credenciales de Supabase
# Prioriza las variables de entorno de tu sistema o archivo .env.
SUPABASE_URL = os.getenv("SUPABASE_URL", "https://tyunqthoinamdlyhgmuq.supabase.co")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InR5dW5xdGhvaW5hbWRseWhnbXVxIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc4MDk2NjM5NSwiZXhwIjoyMDk2NTQyMzk1fQ.bVjJQbQnbVHp9rNAR7Ju7Iu6ioB5Gj-S_Q5Jw-5V9Mw")

if SUPABASE_KEY == "TU_SERVICE_ROLE_KEY_ACTUALIZADA" or not SUPABASE_KEY:
    print("⚠️ ADVERTENCIA: Usando clave por defecto. Si vuelve a fallar con error 401,")
    print("   asegúrate de configurar correctamente tu archivo .env o la variable de entorno.")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)


def generar_uuid(texto_base: str) -> str:
    """Genera un UUID consistente y válido basado en texto (UUIDv5) para Postgres."""
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, texto_base))


def parsear_norma_real(pdf_path: str):
    """
    Lee el PDF oficial de NIST SP 800-53 Rev. 5, extrae dinámicamente
    los controles completos (ej: AC-2, AT-3) de las familias AC, AT e IA,
    y estructura las lecciones en Markdown.
    """
    print(f"📖 Leyendo y parseando documento oficial desde: {pdf_path}")
    
    try:
        reader = PdfReader(pdf_path)
    except Exception as e:
        print(f"❌ Error crítico leyendo el archivo PDF: {str(e)}")
        return []

    total_paginas = len(reader.pages)
    print(f"Total de páginas detectadas en la norma: {total_paginas}")

    controles_encontrados = {}
    
    # 🌟 REGEX CORREGIDO: Captura el control completo en el grupo [0] (ej: AC-2) y la familia en el [1] (ej: AC)
    pattern_control = re.compile(r'\b(([A-Z]{2})-\d+(?:\(\d+\))?)\b')

    # Ajustamos el rango de páginas para procesar una sección sustancial del catálogo de controles
    rango_maximo = min(350, total_paginas) 
    
    for num_pag in range(0, rango_maximo):
        texto = reader.pages[num_pag].extract_text()
        if not texto:
            continue
            
        matches = pattern_control.findall(texto)
        for match in matches:
            ctrl = match[0]        # Ej: 'AC-2' o 'AC-2(1)'
            familia = match[1]     # Ej: 'AC'
            
            # Validamos contra las familias asignadas para este trayecto técnico
            if familia in ['AC', 'AT', 'IA', 'AU']: 
                if ctrl not in controles_encontrados:
                    controles_encontrados[ctrl] = {
                        "domain_id": familia,  # Mapeado a domain_id para mantener consistencia con la tabla
                        "title": f"Estudio Técnico del Control: {ctrl}",
                        "content_lines": [],
                        "mapped_controls": [ctrl]
                    }
                
                # Extracción y limpieza básica de líneas didácticas de la página del PDF
                lineas_limpias = [linea.strip() for linea in texto.split('\n') if len(linea.strip()) > 10]
                extracto = "\n* ".join(lineas_limpias[:5]) 
                
                if extracto and len(controles_encontrados[ctrl]["content_lines"]) < 3:
                    controles_encontrados[ctrl]["content_lines"].append(
                        f"### Especificaciones del Estándar (Pág. {num_pag + 1}):\n* {extracto}"
                    )

    # Estructuración final de los módulos para el payload de Supabase
    datos_academia = []
    for cod_control, info in controles_encontrados.items():
        resumen_contenido = (
            f"# Módulo de Especialización: {cod_control}\n\n"
            f"Este bloque de estudio contiene las directrices, guías de implementación e indicadores "
            f"técnicos dictados por el **NIST SP 800-53 Rev. 5** para el control federado **{cod_control}**.\n\n"
            f"## Contexto General y Objetivos\n"
            f"Garantizar el cumplimiento técnico del control para mitigar vectores de riesgo estructurales "
            f"dentro de la arquitectura del ecosistema Hyperion.\n\n"
            + "\n\n".join(info["content_lines"])
        )
        
        quiz_dinamico = {
            "question": f"¿Cuál es el requerimiento de cumplimiento principal asociado al control {cod_control} según las pautas técnicas del estándar NIST?",
            "options": [
                {"id": "A", "text": "Aplicar de forma estricta las salvaguardas y registrar los logs de auditoría sin omisiones."},
                {"id": "B", "text": "Deshabilitar las restricciones perimetrales para acelerar las respuestas de la API."},
                {"id": "C", "text": "Almacenar tokens de autenticación en texto plano dentro de la base de datos de pruebas."}
            ],
            "correct": "A"
        }
        
        datos_academia.append({
            "domain_id": info["domain_id"],
            "title": info["title"],
            "content": resumen_contenido,
            "duration": 15,
            "controls": info["mapped_controls"],
            "quiz": quiz_dinamico
        })
        
    return datos_academia


def subir_a_supabase(datos):
    if not datos:
        print("⚠️ No se generaron módulos para inyectar. Verifica el archivo PDF o las páginas analizadas.")
        return

    print(f"\n🚀 Iniciando migración masiva segura de {len(datos)} lecciones a Supabase...")
    
    errores = 0
    exitos = 0

    for idx, item in enumerate(datos):
        lesson_id = generar_uuid(item["title"])
        checkpoint_id = generar_uuid(item["quiz"]["question"])
        
        # 🌟 PAYLOAD CORREGIDO: Se inyecta explícitamente "framework": "NIST" y se usa domain_id
        leccion_payload = {
            "id": lesson_id,
            "domain_id": item["domain_id"], 
            "title": item["title"],
            "content_markdown": item["content"],
            "duration_minutes": item["duration"],
            "sort_order": idx + 1,
            "mapped_controls": item["controls"],
            "framework": "NIST"
        }
        
        try:
            # 1. Inyección o actualización de la Lección (Upsert evita duplicados repetidos)
            supabase.table("academy_lessons").upsert(leccion_payload).execute()
            
            # 2. Inyección del Checkpoint evaluativo asociado
            checkpoint_payload = {
                "id": checkpoint_id,
                "lesson_id": lesson_id,
                "question": item["quiz"]["question"],
                "options": item["quiz"]["options"],
                "correct_option_id": item["quiz"]["correct"]
            }
            supabase.table("academy_checkpoints").upsert(checkpoint_payload).execute()
            
            print(f"✅ [{item['domain_id']}] {item['title']} sincronizado [UUID: {lesson_id[:8]}...]")
            exitos += 1
            
        except Exception as e:
            print(f"❌ Error inyectando el control '{item['title']}': {str(e)}")
            errores += 1

    print(f"\n📊 Resumen del proceso: {exitos} exitosos, {errores} fallidos.")


if __name__ == "__main__":
    # Localizar el directorio base donde se ejecuta el script
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    pdf_norma = os.path.join(BASE_DIR, "NIST.SP.800-53r5.pdf")

    if os.path.exists(pdf_norma):
        datos_extraidos = parsear_norma_real(pdf_norma)
        subir_a_supabase(datos_extraidos)
        print("\n🎉 Proceso de sincronización finalizado. ¡Revisa tu frontend de Hyperion!")
    else:
        print(f"❌ No se detectó el archivo PDF en la ruta calculada: {pdf_norma}")
        print("💡 Sugerencia: Asegúrate de colocar el archivo PDF 'NIST.SP.800-53r5.pdf' en la misma carpeta que este script.")