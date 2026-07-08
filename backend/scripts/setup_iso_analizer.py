# setup_iso_analyzer.py
import json
from pathlib import Path

def create_iso_controls():
    """Crear archivo JSON con todos los controles ISO 27001:2022"""
    
    iso_controls = [
        # 37 Controles Organizacionales
        {"id": "5.1", "title": "Políticas de seguridad de la información", "category": "organizational"},
        {"id": "5.2", "title": "Funciones de seguridad de la información", "category": "organizational"},
        {"id": "5.3", "title": "Separación de funciones", "category": "organizational"},
        {"id": "5.4", "title": "Responsabilidades de gestión", "category": "organizational"},
        {"id": "5.5", "title": "Contacto con las autoridades", "category": "organizational"},
        {"id": "5.6", "title": "Contacto con grupos de interés especial", "category": "organizational"},
        {"id": "5.7", "title": "Inteligencia de amenazas", "category": "organizational"},
        {"id": "5.8", "title": "Seguridad de la información en la gestión de proyectos", "category": "organizational"},
        {"id": "5.9", "title": "Inventario de información y otros activos asociados", "category": "organizational"},
        {"id": "5.10", "title": "Uso aceptable de la información", "category": "organizational"},
        {"id": "5.11", "title": "Devolución de activos", "category": "organizational"},
        {"id": "5.12", "title": "Clasificación de la información", "category": "organizational"},
        {"id": "5.13", "title": "Etiquetado de la información", "category": "organizational"},
        {"id": "5.14", "title": "Transferencia de información", "category": "organizational"},
        {"id": "5.15", "title": "Control de acceso", "category": "organizational"},
        {"id": "5.16", "title": "Gestión de identidades", "category": "organizational"},
        {"id": "5.17", "title": "Información de autenticación", "category": "organizational"},
        {"id": "5.18", "title": "Derechos de acceso", "category": "organizational"},
        {"id": "5.19", "title": "Seguridad en relaciones con proveedores", "category": "organizational"},
        {"id": "5.20", "title": "Acuerdos con proveedores", "category": "organizational"},
        {"id": "5.21", "title": "Seguridad en cadena de suministro TIC", "category": "organizational"},
        {"id": "5.22", "title": "Monitoreo de servicios de proveedores", "category": "organizational"},
        {"id": "5.23", "title": "Seguridad para servicios en la nube", "category": "organizational"},
        {"id": "5.24", "title": "Planificación de incidentes", "category": "organizational"},
        {"id": "5.25", "title": "Evaluación de eventos", "category": "organizational"},
        {"id": "5.26", "title": "Respuesta a incidentes", "category": "organizational"},
        {"id": "5.27", "title": "Aprendizaje de incidentes", "category": "organizational"},
        {"id": "5.28", "title": "Obtención de pruebas", "category": "organizational"},
        {"id": "5.29", "title": "Seguridad durante interrupciones", "category": "organizational"},
        {"id": "5.30", "title": "Preparación TIC", "category": "organizational"},
        {"id": "5.31", "title": "Requisitos legales", "category": "organizational"},
        {"id": "5.32", "title": "Derechos de propiedad intelectual", "category": "organizational"},
        {"id": "5.33", "title": "Protección de registros", "category": "organizational"},
        {"id": "5.34", "title": "Privacidad y PII", "category": "organizational"},
        {"id": "5.35", "title": "Revisión independiente", "category": "organizational"},
        {"id": "5.36", "title": "Cumplimiento de políticas", "category": "organizational"},
        {"id": "5.37", "title": "Procedimientos operativos", "category": "organizational"},
        
        # 8 Controles de Personas
        {"id": "6.1", "title": "Verificación de antecedentes", "category": "people"},
        {"id": "6.2", "title": "Términos de empleo", "category": "people"},
        {"id": "6.3", "title": "Concienciación y capacitación", "category": "people"},
        {"id": "6.4", "title": "Proceso disciplinario", "category": "people"},
        {"id": "6.5", "title": "Responsabilidades post-empleo", "category": "people"},
        {"id": "6.6", "title": "Acuerdos de confidencialidad", "category": "people"},
        {"id": "6.7", "title": "Trabajo remoto", "category": "people"},
        {"id": "6.8", "title": "Reporte de eventos", "category": "people"},
        
        # 14 Controles Físicos
        {"id": "7.1", "title": "Perímetros de seguridad física", "category": "physical"},
        {"id": "7.2", "title": "Control de entrada físico", "category": "physical"},
        {"id": "7.3", "title": "Seguridad de oficinas", "category": "physical"},
        {"id": "7.4", "title": "Monitoreo de seguridad física", "category": "physical"},
        {"id": "7.5", "title": "Protección contra amenazas físicas", "category": "physical"},
        {"id": "7.6", "title": "Trabajo en áreas seguras", "category": "physical"},
        {"id": "7.7", "title": "Escritorio y pantalla limpia", "category": "physical"},
        {"id": "7.8", "title": "Ubicación de equipos", "category": "physical"},
        {"id": "7.9", "title": "Seguridad de activos externos", "category": "physical"},
        {"id": "7.10", "title": "Medios de almacenamiento", "category": "physical"},
        {"id": "7.11", "title": "Servicios de soporte", "category": "physical"},
        {"id": "7.12", "title": "Seguridad del cableado", "category": "physical"},
        {"id": "7.13", "title": "Mantenimiento de equipos", "category": "physical"},
        {"id": "7.14", "title": "Eliminación segura", "category": "physical"},
        
        # 34 Controles Tecnológicos
        {"id": "8.1", "title": "Dispositivos de punto final", "category": "technological"},
        {"id": "8.2", "title": "Derechos de acceso privilegiados", "category": "technological"},
        {"id": "8.3", "title": "Restricción de acceso", "category": "technological"},
        {"id": "8.4", "title": "Acceso al código fuente", "category": "technological"},
        {"id": "8.5", "title": "Autenticación segura", "category": "technological"},
        {"id": "8.6", "title": "Gestión de capacidad", "category": "technological"},
        {"id": "8.7", "title": "Protección contra malware", "category": "technological"},
        {"id": "8.8", "title": "Gestión de vulnerabilidades", "category": "technological"},
        {"id": "8.9", "title": "Gestión de configuración", "category": "technological"},
        {"id": "8.10", "title": "Eliminación de información", "category": "technological"},
        {"id": "8.11", "title": "Enmascaramiento de datos", "category": "technological"},
        {"id": "8.12", "title": "Prevención de fuga de datos", "category": "technological"},
        {"id": "8.13", "title": "Copia de seguridad", "category": "technological"},
        {"id": "8.14", "title": "Redundancia", "category": "technological"},
        {"id": "8.15", "title": "Registro", "category": "technological"},
        {"id": "8.16", "title": "Monitoreo de actividades", "category": "technological"},
        {"id": "8.17", "title": "Sincronización de relojes", "category": "technological"},
        {"id": "8.18", "title": "Programas privilegiados", "category": "technological"},
        {"id": "8.19", "title": "Instalación de software", "category": "technological"},
        {"id": "8.20", "title": "Seguridad de redes", "category": "technological"},
        {"id": "8.21", "title": "Seguridad de servicios de red", "category": "technological"},
        {"id": "8.22", "title": "Segregación de redes", "category": "technological"},
        {"id": "8.23", "title": "Filtrado web", "category": "technological"},
        {"id": "8.24", "title": "Criptografía", "category": "technological"},
        {"id": "8.25", "title": "Ciclo de vida de desarrollo seguro", "category": "technological"},
        {"id": "8.26", "title": "Requisitos de seguridad", "category": "technological"},
        {"id": "8.27", "title": "Arquitectura segura", "category": "technological"},
        {"id": "8.28", "title": "Codificación segura", "category": "technological"},
        {"id": "8.29", "title": "Pruebas de seguridad", "category": "technological"},
        {"id": "8.30", "title": "Desarrollo externalizado", "category": "technological"},
        {"id": "8.31", "title": "Separación de entornos", "category": "technological"},
        {"id": "8.32", "title": "Gestión de cambios", "category": "technological"},
        {"id": "8.33", "title": "Información de pruebas", "category": "technological"},
        {"id": "8.34", "title": "Protección durante auditorías", "category": "technological"},
    ]
    
    # Crear la estructura completa
    data = {
        "standard": "ISO/IEC 27001:2022",
        "version": "2022",
        "description": "Tecnología de la información — Técnicas de seguridad — Sistemas de gestión de la seguridad de la información — Requisitos",
        "total_controls": len(iso_controls),
        "controls_by_category": {
            "organizational": len([c for c in iso_controls if c["category"] == "organizational"]),
            "people": len([c for c in iso_controls if c["category"] == "people"]),
            "physical": len([c for c in iso_controls if c["category"] == "physical"]),
            "technological": len([c for c in iso_controls if c["category"] == "technological"])
        },
        "controls": iso_controls
    }
    
    # Asegurar que encuentre la raíz del backend sin importar desde dónde se ejecute
    backend_root = Path(__file__).parent.parent if Path(__file__).parent.name == "scripts" else Path(__file__).parent
    data_dir = backend_root / "app" / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    
    # Guardar archivo en la ubicación correcta global
    output_file = data_dir / "iso_controls.json"
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    
    print(f"✅ Archivo creado: {output_file}")
    print("\n📊 Resumen ISO 27001:2022")
    print(f"   Total controles: {data['total_controls']}")
    print(f"   Organizacionales: {data['controls_by_category']['organizational']}")
    print(f"   Personas: {data['controls_by_category']['people']}")
    print(f"   Físicos: {data['controls_by_category']['physical']}")
    print(f"   Tecnológicos: {data['controls_by_category']['technological']}")
    
    return data

if __name__ == "__main__":
    create_iso_controls()
    print("\n✅ Configuración completada!")