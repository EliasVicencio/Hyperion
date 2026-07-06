# scripts/load_iso_academy.py
import asyncio
import sys
import os
import uuid
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from dotenv import load_dotenv
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import text

load_dotenv(Path(__file__).parent.parent / ".env")

DATABASE_URL = os.getenv("DATABASE_URL") or os.getenv("BACKEND_URL")
if not DATABASE_URL:
    print("❌ Error: No se encontró DATABASE_URL.")
    sys.exit(1)

if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+asyncpg://", 1)
elif DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://", 1)

async_engine = create_async_engine(DATABASE_URL, echo=False)
AsyncSessionLocal = sessionmaker(async_engine, class_=AsyncSession, expire_on_commit=False)

async def seed_iso_academy():
    print("🌍 [HYPERION] Inicializando academia con los controles REALES extraídos...")
    
    backend_root = Path(__file__).parent.parent if Path(__file__).parent.name == "scripts" else Path(__file__).parent
    iso_json_path = backend_root / "app" / "data" / "iso_controls.json"
    
    if not iso_json_path.exists():
        print(f"⚠️ No se encontró el archivo: {iso_json_path}")
        return

    with open(iso_json_path, 'r', encoding='utf-8') as f:
        iso_data = json.load(f)
    
    all_controls = iso_data.get("controls", [])
    print(f"📊 Procesando {len(all_controls)} controles reales de la ISO 27001:2022.")

    async with AsyncSessionLocal() as session:
        try:
            print("🧹 Limpiando registros académicos previos en cascada...")
            await session.execute(text("TRUNCATE TABLE academy_checkpoints CASCADE;"))
            await session.execute(text("TRUNCATE TABLE academy_lessons CASCADE;"))
            await session.execute(text("TRUNCATE TABLE iso_domains CASCADE;"))
            
            print("📁 Cargando los 4 pilares estructurales del Anexo A...")
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

            sql_lessons = text("""
                INSERT INTO academy_lessons (id, domain_id, title, duration_minutes, mapped_controls, content_markdown, sort_order) 
                VALUES (:id, :domain_id, :title, :duration_minutes, :mapped_controls, :content_markdown, :sort_order);
            """)
            sql_checkpoints = text("""
                INSERT INTO academy_checkpoints (id, lesson_id, question, options, correct_option_id) 
                VALUES (:id, :lesson_id, :question, :options, :correct_option_id);
            """)

            domain_map = {
                "organizational": "A.5",
                "people": "A.6",
                "physical": "A.7",
                "technological": "A.8"
            }

            sort_order = 1
            for control in all_controls:
                raw_id = control.get("id", "N/A")
                title_real = control.get("title", "Sin título oficial")
                category = control.get("category", "technological")
                description_real = control.get("description", "Lineamientos de control y gobernanza operativa.")

                domain_id = domain_map.get(category, "A.8")
                iso_label = f"A.{raw_id}" if not str(raw_id).startswith("A.") else raw_id
                lesson_id = str(uuid.uuid4())

                # Generar contenido Markdown dinámico y enriquecido según el control real
                content_markdown = (
                    f"# Control {iso_label} - {title_real}\n\n"
                    f"## 📋 Descripción Oficial de la Norma\n"
                    f"{description_real}\n\n"
                    f"## 🛡️ Propósito del Control\n"
                    f"Establecer salvaguardas operativas en el dominio **{domain_id}** para mitigar los riesgos asociados a este activo o proceso.\n\n"
                    f"## ⚙️ Evaluación y Evidencia en Hyperion\n"
                    f"La plataforma valida este control mediante la recolección automática de evidencias y logs auditables. Asegúrate de mapear las políticas internas del SGSI con este identificador normativo."
                )

                await session.execute(sql_lessons, {
                    "id": lesson_id,
                    "domain_id": domain_id,
                    "title": f"Control {iso_label}: {title_real}",
                    "duration_minutes": 15,
                    "mapped_controls": [iso_label],
                    "content_markdown": content_markdown,
                    "sort_order": sort_order
                })

                # Generar preguntas de Quiz dinámicas e inteligentes basadas en la categoría
                if category == "organizational":
                    question = f"Para cumplir con el control organizacional {iso_label} ({title_real}), ¿cuál es la acción primordial de la alta dirección?"
                    options = [
                        {"id": "A", "text": "Delegar la seguridad exclusivamente al equipo de desarrollo sin supervisión."},
                        {"id": "B", "text": "Aprobar, publicar y revisar periódicamente las políticas de seguridad alineadas al negocio."},
                        {"id": "C", "text": "Evitar documentar los procesos para acelerar la operación de la empresa."}
                    ]
                elif category == "people":
                    question = f"Bajo los lineamientos del control de personas {iso_label}, ¿cuándo debe impartirse la concientización en seguridad?"
                    options = [
                        {"id": "A", "text": "Únicamente después de que ocurra un incidente crítico de filtración."},
                        {"id": "B", "text": "De forma regular y sistemática a todos los empleados desde su contratación."},
                        {"id": "C", "text": "Solo al personal del área de tecnología e infraestructura informática."}
                    ]
                elif category == "physical":
                    question = f"¿Cuál es un requerimiento clave para mitigar riesgos en el control físico {iso_label} ({title_real})?"
                    options = [
                        {"id": "A", "text": "Permitir el acceso libre a las instalaciones para agilizar visitas."},
                        {"id": "B", "text": "Definir y proteger perímetros físicos, controlando los accesos a áreas críticas mediante autenticación."},
                        {"id": "C", "text": "Confiar plenamente en la seguridad pública externa sin controles propios."}
                    ]
                else: # technological
                    question = f"En el ámbito del control tecnológico {iso_label} ({title_real}), ¿qué práctica asegura la resiliencia técnica?"
                    options = [
                        {"id": "A", "text": "Desactivar los sistemas de monitoreo para ahorrar espacio de almacenamiento."},
                        {"id": "B", "text": "Implementar configuraciones seguras, cifrado y control de accesos basados en privilegios mínimos."},
                        {"id": "C", "text": "Utilizar la misma contraseña maestra en todos los servicios de red."}
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
            print(f"✅ [HYPERION] ¡Base de datos académica inyectada con éxito! {len(all_controls)} controles distribuidos en todos los dominios.")

        except Exception as e:
            await session.rollback()
            print(f"❌ Error durante la siembra masiva: {str(e)}")
        finally:
            await async_engine.dispose()

if __name__ == "__main__":
    asyncio.run(seed_iso_academy())