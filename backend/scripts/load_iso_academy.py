# scripts/load_iso_academy.py
import asyncio
import sys
import os
import uuid
import json
from pathlib import Path

# Agregar el directorio raíz al path por si acaso
sys.path.insert(0, str(Path(__file__).parent.parent))

from dotenv import load_dotenv
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import text

# Cargar las variables de entorno de tu archivo .env
load_dotenv(Path(__file__).parent.parent / ".env")

# 1. Configurar la URL asíncrona de la base de datos
DATABASE_URL = os.getenv("DATABASE_URL") or os.getenv("BACKEND_URL")

if not DATABASE_URL:
    print("❌ Error: No se encontró DATABASE_URL en las variables de entorno (.env)")
    sys.exit(1)

# Asegurar que use el driver asíncrono asyncpg para PostgreSQL
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+asyncpg://", 1)
elif DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://", 1)

# 2. Crear el motor asíncrono y la fábrica de sesiones de forma independiente
async_engine = create_async_engine(DATABASE_URL, echo=False)
AsyncSessionLocal = sessionmaker(async_engine, class_=AsyncSession, expire_on_commit=False)

async def seed_iso_academy():
    print("🌍 [HYPERION] Inicializando academia con los controles REALES extraídos...")
    
    # Buscar el JSON en la ubicación global (app/data/iso_controls.json) que creó setup_iso_analyzer.py
    backend_root = Path(__file__).parent.parent if Path(__file__).parent.name == "scripts" else Path(__file__).parent
    iso_json_path = backend_root / "app" / "data" / "iso_controls.json"
    
    if not iso_json_path.exists():
        print(f"⚠️ No se encontró el archivo: {iso_json_path}")
        print("Por favor, ejecuta primero: python scripts/setup_iso_analyzer.py")
        return

    with open(iso_json_path, 'r', encoding='utf-8') as f:
        iso_data = json.load(f)
    
    all_controls = iso_data.get("controls", [])
    print(f"📊 Procesando {len(all_controls)} controles reales de la ISO 27001:2022.")

    # Conexión usando el gestor de contexto asíncrono local seguro
    async with AsyncSessionLocal() as session:
        try:
            print("🧹 Limpiando registros académicos previos en cascada...")
            await session.execute(text("TRUNCATE TABLE academy_checkpoints CASCADE;"))
            await session.execute(text("TRUNCATE TABLE academy_lessons CASCADE;"))
            await session.execute(text("TRUNCATE TABLE iso_domains CASCADE;"))
            
            # 1. Insertar la estructura limpia de los 4 Dominios Oficiales de la ISO 27001:2022
            print("📁 Cargando los 4 pilares del Anexo A...")
            sql_domains = text("""
                INSERT INTO iso_domains (id, name, description) VALUES
                (:id5, :name5, :desc5),
                (:id6, :name6, :desc6),
                (:id7, :name7, :desc7),
                (:id8, :name8, :desc8);
            """)
            await session.execute(sql_domains, {
                "id5": "A.5", "name5": "Controles Organizacionales", "desc5": "Políticas de seguridad, gestión de activos, relaciones con proveedores y cumplimiento corporativo.",
                "id6": "A.6", "name6": "Controles de Personas", "desc6": "Recursos humanos, términos de empleo, concientización y capacitación técnica de seguridad.",
                "id7": "A.7", "name7": "Controles Físicos", "desc7": "Perímetros de seguridad, protección de instalaciones, monitoreo físico y resguardo de equipos.",
                "id8": "A.8", "name8": "Controles Tecnológicos", "desc8": "Cifrado avanzado, criptografía, seguridad en redes, ingeniería de sistemas y desarrollo seguro."
            })

            # 2. Mapear dinámicamente controles reales leídos de tu JSON a lecciones didácticas
            print("📝 Vinculando controles del JSON a los módulos académicos...")
            sql_lessons = text("""
                INSERT INTO academy_lessons (id, domain_id, title, duration_minutes, mapped_controls, content_markdown, sort_order) 
                VALUES (:id, :domain_id, :title, :duration_minutes, :mapped_controls, :content_markdown, :sort_order);
            """)
            sql_checkpoints = text("""
                INSERT INTO academy_checkpoints (id, lesson_id, question, options, correct_option_id) 
                VALUES (:id, :lesson_id, :question, :options, :correct_option_id);
            """)

            sort_order = 1
            for control in all_controls:
                raw_id = control.get("id", "N/A")  # Ej: "8.24", "8.20"
                title_real = control.get("title", "Sin título oficial")
                category = control.get("category", "technological")

                # Mapeo de categorías al formato oficial de dominios
                domain_map = {
                    "organizational": "A.5",
                    "people": "A.6",
                    "physical": "A.7",
                    "technological": "A.8"
                }
                domain_id = domain_map.get(category, "A.8")

                # Alimentamos la academia con los controles estructurales críticos (Criptografía y Redes)
                if raw_id in ["8.24", "8.20"]:
                    lesson_id = str(uuid.uuid4())
                    iso_label = f"A.{raw_id}"
                    
                    print(f"   ↳ Inyectando Lección fidedigna para {iso_label}: {title_real}")
                    
                    content_markdown = (
                        f"# Control {iso_label} - {title_real}\n\n"
                        f"## Descripción Oficial de la Norma\n"
                        f"Lineamientos e indicaciones para el control técnico de **{title_real}** establecido en el estándar internacional de seguridad.\n\n"
                        f"## Evaluación de Cumplimiento en Hyperion\n"
                        f"Asegura la recolección automática de evidencias asociadas a este control utilizando los módulos de auditoría interna de la plataforma."
                    )

                    await session.execute(sql_lessons, {
                        "id": lesson_id,
                        "domain_id": domain_id,
                        "title": f"Control {iso_label}: {title_real}",
                        "duration_minutes": 15 if raw_id == "8.24" else 20,
                        "mapped_controls": [iso_label],
                        "content_markdown": content_markdown,
                        "sort_order": sort_order
                    })

                    # Insertar Checkpoint de evaluación correspondiente
                    if raw_id == "8.24":
                        question = f"¿Cuál es el enfoque principal del control {iso_label} ({title_real})?"
                        options = [
                            {"id": "A", "text": "Evitar el uso de cualquier algoritmo criptográfico para simplificar el código del sistema."},
                            {"id": "B", "text": f"Garantizar el uso adecuado y eficaz de la criptografía para proteger la información según los requisitos del negocio."},
                            {"id": "C", "text": "Habilitar el acceso sin autenticación a las tablas de Supabase."}
                        ]
                    else:  # 8.20
                        question = f"Según las directrices de la norma para el control {iso_label} ({title_real}), ¿cómo debe protegerse la información?"
                        options = [
                            {"id": "A", "text": "Manteniendo una red abierta sin segmentación ni firewalls."},
                            {"id": "B", "text": f"Mediante la gestión, control y segregación adecuada de las redes y los recursos de procesamiento conectados."},
                            {"id": "C", "text": "Inhabilitando por completo los protocolos TLS y SSH."}
                        ]

                    await session.execute(sql_checkpoints, {
                        "id": str(uuid.uuid4()),
                        "lesson_id": lesson_id,
                        "question": question,
                        "options": json.dumps(options, ensure_ascii=False),
                        "correct_option_id": "B"
                    })
                    
                    sort_order += 1

            await session.commit()
            print("✅ [HYPERION] ¡Base de datos académica inyectada con éxito de forma asíncrona autónoma!")

        except Exception as e:
            await session.rollback()
            print(f"❌ Error durante el proceso de siembra en PostgreSQL: {str(e)}")
        finally:
            await async_engine.dispose()

if __name__ == "__main__":
    asyncio.run(seed_iso_academy())