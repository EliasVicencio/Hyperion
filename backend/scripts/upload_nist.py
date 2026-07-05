import os
import uuid
import re
from supabase import create_client, Client
from pypdf import PdfReader

# 1. Configuración de Credenciales de Supabase
# Recomiendo configurar estas variables en el archivo .env de tu backend
SUPABASE_URL = os.getenv("SUPABASE_URL", "https://tyunqthoinamdlyhgmuq.supabase.co")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InR5dW5xdGhvaW5hbWRseWhnbXVxIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc4MDk2NjM5NSwiZXhwIjoyMDk2NTQyMzk1fQ.bVjJQbQnbVHp9rNAR7Ju7Iu6ioB5Gj-S_Q5Jw-5V9Mw")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

def generar_uuid(texto_base: str) -> str:
    """Genera un UUID consistente y válido basado en texto (UUIDv5) para Postgres."""
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, texto_base))

def parsear_norma_real(pdf_path: str):
    """
    Lee el PDF oficial de NIST SP 800-53 Rev. 5 guardado en la carpeta del proyecto,
    extrae dinámicamente los controles de las familias AC, AT e IA, y arma las lecciones.
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
    
    # Expresión regular robusta para capturar controles como AC-2, AC-6, AT-3, IA-2
    pattern_control = re.compile(r'\b([A-Z]{2})-\d+(?:\(\d+\))?\b')

    # Ajusta este rango según las páginas clave de controles de tu PDF para optimizar la velocidad
    rango_maximo = min(250, total_paginas) 
    
    for num_pag in range(0, rango_maximo):
        texto = reader.pages[num_pag].extract_text()
        if not texto:
            continue
            
        matches = pattern_control.findall(texto)
        for ctrl in matches:
            familia = ctrl[:2]
            # Validamos contra las familias que ya tienes dadas de alta en la tabla nist_families
            if familia in ['AC', 'AT', 'IA']: 
                if ctrl not in controles_encontrados:
                    controles_encontrados[ctrl] = {
                        "family_id": familia,
                        "title": f"Estudio Técnico del Control: {ctrl}",
                        "content_lines": [],
                        "mapped_controls": [ctrl]
                    }
                
                # Extraemos líneas del PDF para estructurar el contenido didáctico en Markdown
                lineas_limpias = [linea.strip() for linea in texto.split('\n') if len(linea.strip()) > 10]
                extracto = "\n* ".join(lineas_limpias[:5]) # Tomamos puntos clave detectados en la página
                
                if extracto and len(controles_encontrados[ctrl]["content_lines"]) < 3:
                    controles_encontrados[ctrl]["content_lines"].append(
                        f"### Especificaciones del Estándar (Pág. {num_pag + 1}):\n* {extracto}"
                    )

    # Estructuración final de los módulos listos para Supabase
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
        
        # Quiz técnico dinámico adaptado al control iterado con opciones formateadas en JSONB
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
            "family_id": info["family_id"],
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
    
    for idx, item in enumerate(datos):
        # Generación segura de UUIDs deterministas para respetar la restricción UUID de Postgres
        lesson_id = generar_uuid(item["title"])
        checkpoint_id = generar_uuid(item["quiz"]["question"])
        
        leccion_payload = {
            "id": lesson_id,
            "family_id": item["family_id"],
            "title": item["title"],
            "content_markdown": item["content"],
            "duration_minutes": item["duration"],
            "sort_order": idx + 1,
            "mapped_controls": item["controls"]
        }
        
        try:
            # 1. Inyección o actualización de la Lección (Evita duplicados usando upsert)
            supabase.table("academy_lessons").upsert(leccion_payload).execute()
            print(f"✅ [{item['family_id']}] Lección sincronizada con éxito [UUID: {lesson_id[:8]}...]")
            
            # 2. Inyección del Checkpoint enlazado correctamente mediante el UUID de la lección
            checkpoint_payload = {
                "id": checkpoint_id,
                "lesson_id": lesson_id,
                "question": item["quiz"]["question"],
                "options": item["quiz"]["options"],
                "correct_option_id": item["correct_option_id"] if "correct_option_id" in item else item["quiz"]["correct"]
            }
            
            supabase.table("academy_checkpoints").upsert(checkpoint_payload).execute()
            
        except Exception as e:
            print(f"❌ Error inyectando el control {item['title']}: {str(e)}")

if __name__ == "__main__":
    # 🌟 RUTAS DINÁMICAS ABSOLUTAS:
    # Detecta el directorio exacto donde guardaste este script .py
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    
    # OPCIÓN A: Si pones el PDF en la misma carpeta que el script:
    pdf_norma = os.path.join(BASE_DIR, "NIST.SP.800-53r5.pdf")
    
    # OPCIÓN B: Si creas una subcarpeta de archivos dedicada (ej: "archivos/NIST.SP.800-53r5.pdf")
    # Descomenta la línea de abajo si prefieres esta estructura:
    # pdf_norma = os.path.join(BASE_DIR, "archivos", "NIST.SP.800-53r5.pdf")

    if os.path.exists(pdf_norma):
        datos_extraidos = parsear_norma_real(pdf_norma)
        subir_a_supabase(datos_extraidos)
        print("\n🎉 ¡Sincronización masiva finalizada con éxito! Actualiza tu frontend de Hyperion.")
    else:
        print(f"❌ No se detectó el archivo PDF en la ruta calculada: {pdf_norma}")
        print("💡 Sugerencia: Asegúrate de arrastrar el archivo PDF 'NIST.SP.800-53r5.pdf' al directorio indicado arriba.")