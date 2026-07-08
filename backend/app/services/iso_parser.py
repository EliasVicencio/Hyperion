# app/services/iso_parser.py
from typing import Dict, List
from dataclasses import dataclass

@dataclass
class ISOSection:
    """Representa una sección de la norma ISO 27001"""
    number: str
    title: str
    content: str
    requirements: List[str]

class ISOParser:
    """Parsea el documento PDF de ISO 27001:2022"""
    
    def __init__(self, pdf_path: str = None):
        self.pdf_path = pdf_path
        self.sections = []
        self.controls = []
        
    def parse_standard(self):
        """Parser principal de la norma"""
        # Extraer controles del Anexo A
        controls = self._extract_controls()
        
        # Extraer requisitos principales (Cláusulas 4-10)
        requirements = self._extract_requirements()
        
        return {
            "controls": controls,
            "requirements": requirements,
            "version": "ISO/IEC 27001:2022"
        }
    
    def _extract_controls(self) -> List[Dict]:
        """Extrae los 93 controles del Anexo A"""
        controls = []
        
        # Controles organizacionales (Cláusula 5)
        organizational_controls = [
            {"id": "5.1", "title": "Políticas de seguridad de la información", 
             "description": "La política de seguridad de la información será definida, aprobada, publicada y comunicada."},
            {"id": "5.2", "title": "Funciones de seguridad de la información", 
             "description": "Los roles y responsabilidades de seguridad de la información deben definirse y asignarse."},
            {"id": "5.3", "title": "Separación de funciones", 
             "description": "Se determinarán las funciones conflictivas y los ámbitos de responsabilidad contradictorios."},
            {"id": "5.4", "title": "Responsabilidades de gestión", 
             "description": "La gerencia requerirá que todo el personal aplique la seguridad de la información."},
            {"id": "5.5", "title": "Contacto con las autoridades", 
             "description": "La organización debe establecer y mantener contacto con las autoridades pertinentes."},
            {"id": "5.6", "title": "Contacto con grupos de interés especial", 
             "description": "La organización debe establecer y mantener contacto con grupos de interés especial."},
            {"id": "5.7", "title": "Inteligencia de amenazas", 
             "description": "La información sobre amenazas se recopilará y analizará."},
            {"id": "5.8", "title": "Seguridad de la información en la gestión de proyectos", 
             "description": "La seguridad de la información se integrará en la gestión del proyecto."},
            {"id": "5.9", "title": "Inventario de información y otros activos", 
             "description": "Se elaborará un inventario de la información y otros activos asociados."},
            {"id": "5.10", "title": "Uso aceptable de la información", 
             "description": "Se identificarán normas para el uso aceptable de la información."},
            {"id": "5.11", "title": "Devolución de activos", 
             "description": "El personal devolverá todos los activos al terminar su empleo."},
            {"id": "5.12", "title": "Clasificación de la información", 
             "description": "La información se clasificará según necesidades de seguridad."},
            {"id": "5.13", "title": "Etiquetado de la información", 
             "description": "Se aplicarán procedimientos para el etiquetado de la información."},
            {"id": "5.14", "title": "Transferencia de información", 
             "description": "Las reglas de transferencia de información deben estar establecidas."},
            {"id": "5.15", "title": "Control de acceso", 
             "description": "Se establecerán normas para controlar el acceso."},
            {"id": "5.16", "title": "Gestión de identidades", 
             "description": "El ciclo de vida completo de las identidades debe gestionarse."},
            {"id": "5.17", "title": "Información de autenticación", 
             "description": "La gestión de información de autenticación se controlará."},
            {"id": "5.18", "title": "Derechos de acceso", 
             "description": "Los derechos de acceso se aprovisionarán y revisarán."},
            {"id": "5.19", "title": "Seguridad en relaciones con proveedores", 
             "description": "Se gestionarán los riesgos asociados con proveedores."},
            {"id": "5.20", "title": "Acuerdos con proveedores", 
             "description": "Requisitos de seguridad se establecerán con cada proveedor."},
            {"id": "5.21", "title": "Seguridad en cadena de suministro TIC", 
             "description": "Se gestionarán riesgos en cadena de suministro TIC."},
            {"id": "5.22", "title": "Monitoreo de servicios de proveedores", 
             "description": "Se monitorearán las prácticas de seguridad del proveedor."},
            {"id": "5.23", "title": "Seguridad para servicios en la nube", 
             "description": "Procesos para adquisición y uso de servicios en la nube."},
            {"id": "5.24", "title": "Planificación de incidentes", 
             "description": "Planificación para la gestión de incidentes."},
            {"id": "5.25", "title": "Evaluación de eventos", 
             "description": "Evaluar eventos de seguridad de la información."},
            {"id": "5.26", "title": "Respuesta a incidentes", 
             "description": "Responder a incidentes según procedimientos."},
            {"id": "5.27", "title": "Aprendizaje de incidentes", 
             "description": "Usar conocimientos de incidentes para mejorar."},
            {"id": "5.28", "title": "Obtención de pruebas", 
             "description": "Procedimientos para recolección de evidencia."},
            {"id": "5.29", "title": "Seguridad durante interrupciones", 
             "description": "Planificar seguridad durante interrupciones."},
            {"id": "5.30", "title": "Preparación TIC", 
             "description": "Planificación de continuidad de TIC."},
            {"id": "5.31", "title": "Requisitos legales", 
             "description": "Identificar requisitos legales aplicables."},
            {"id": "5.32", "title": "Derechos de propiedad intelectual", 
             "description": "Proteger derechos de propiedad intelectual."},
            {"id": "5.33", "title": "Protección de registros", 
             "description": "Registros protegidos contra pérdida."},
            {"id": "5.34", "title": "Privacidad y PII", 
             "description": "Cumplir requisitos de privacidad."},
            {"id": "5.35", "title": "Revisión independiente", 
             "description": "Revisar enfoque de seguridad independientemente."},
            {"id": "5.36", "title": "Cumplimiento de políticas", 
             "description": "Revisar cumplimiento de políticas."},
            {"id": "5.37", "title": "Procedimientos operativos", 
             "description": "Documentar procedimientos operativos."},
        ]
        
        # Controles de personas (Cláusula 6)
        people_controls = [
            {"id": "6.1", "title": "Verificación de antecedentes", 
             "description": "Verificaciones previas a la contratación."},
            {"id": "6.2", "title": "Términos de empleo", 
             "description": "Responsabilidades en contratos laborales."},
            {"id": "6.3", "title": "Concienciación y capacitación", 
             "description": "Programas de concienciación en seguridad."},
            {"id": "6.4", "title": "Proceso disciplinario", 
             "description": "Procedimientos disciplinarios."},
            {"id": "6.5", "title": "Responsabilidades post-empleo", 
             "description": "Responsabilidades tras terminar empleo."},
            {"id": "6.6", "title": "Acuerdos de confidencialidad", 
             "description": "Acuerdos de confidencialidad."},
            {"id": "6.7", "title": "Trabajo remoto", 
             "description": "Medidas para trabajo remoto."},
            {"id": "6.8", "title": "Reporte de eventos", 
             "description": "Mecanismo para reportar incidentes."},
        ]
        
        # Controles físicos (Cláusula 7)
        physical_controls = [
            {"id": "7.1", "title": "Perímetros de seguridad física",
             "description": "Perímetros definidos para protección."},
            {"id": "7.2", "title": "Control de entrada físico",
             "description": "Controles en puntos de acceso."},
            {"id": "7.3", "title": "Seguridad de oficinas",
             "description": "Seguridad física de instalaciones."},
            {"id": "7.4", "title": "Monitoreo de seguridad física",
             "description": "Monitoreo continuo de acceso."},
            {"id": "7.5", "title": "Protección contra amenazas físicas",
             "description": "Protección contra desastres naturales."},
            {"id": "7.6", "title": "Trabajo en áreas seguras",
             "description": "Medidas para áreas seguras."},
            {"id": "7.7", "title": "Escritorio y pantalla limpia",
             "description": "Normas de escritorio claro."},
            {"id": "7.8", "title": "Ubicación de equipos",
             "description": "Equipos protegidos adecuadamente."},
            {"id": "7.9", "title": "Seguridad de activos externos",
             "description": "Protección de activos externos."},
            {"id": "7.10", "title": "Medios de almacenamiento",
             "description": "Gestión de medios de almacenamiento."},
            {"id": "7.11", "title": "Servicios de soporte",
             "description": "Protección contra fallos de suministro."},
            {"id": "7.12", "title": "Seguridad del cableado",
             "description": "Cables protegidos contra interceptación."},
            {"id": "7.13", "title": "Mantenimiento de equipos",
             "description": "Mantenimiento correcto de equipos."},
            {"id": "7.14", "title": "Eliminación segura",
             "description": "Eliminación segura de equipos."},
        ]
        
        # Controles tecnológicos (Cláusula 8)
        technological_controls = [
            {"id": "8.1", "title": "Dispositivos de punto final",
             "description": "Protección de dispositivos de punto final."},
            {"id": "8.2", "title": "Derechos de acceso privilegiados",
             "description": "Gestión de accesos privilegiados."},
            {"id": "8.3", "title": "Restricción de acceso",
             "description": "Acceso restringido según política."},
            {"id": "8.4", "title": "Acceso al código fuente",
             "description": "Gestión de acceso al código."},
            {"id": "8.5", "title": "Autenticación segura",
             "description": "Tecnologías de autenticación segura."},
            {"id": "8.6", "title": "Gestión de capacidad",
             "description": "Monitoreo de uso de recursos."},
            {"id": "8.7", "title": "Protección contra malware",
             "description": "Protección antivirus y antimalware."},
            {"id": "8.8", "title": "Gestión de vulnerabilidades",
             "description": "Identificar vulnerabilidades técnicas."},
            {"id": "8.9", "title": "Gestión de configuración",
             "description": "Configuraciones de seguridad documentadas."},
            {"id": "8.10", "title": "Eliminación de información",
             "description": "Eliminar información cuando sea necesario."},
            {"id": "8.11", "title": "Enmascaramiento de datos",
             "description": "Técnicas de enmascaramiento."},
            {"id": "8.12", "title": "Prevención de fuga de datos",
             "description": "Medidas DLP implementadas."},
            {"id": "8.13", "title": "Copia de seguridad",
             "description": "Copias de seguridad mantenidas."},
            {"id": "8.14", "title": "Redundancia",
             "description": "Redundancia para disponibilidad."},
            {"id": "8.15", "title": "Registro",
             "description": "Generación de logs."},
            {"id": "8.16", "title": "Monitoreo de actividades",
             "description": "Monitoreo de comportamientos anómalos."},
            {"id": "8.17", "title": "Sincronización de relojes",
             "description": "Sincronización con fuentes de tiempo."},
            {"id": "8.18", "title": "Programas privilegiados",
             "description": "Restricción de utilitarios privilegiados."},
            {"id": "8.19", "title": "Instalación de software",
             "description": "Gestión segura de instalación."},
            {"id": "8.20", "title": "Seguridad de redes",
             "description": "Protección de redes."},
            {"id": "8.21", "title": "Seguridad de servicios de red",
             "description": "Mecanismos de seguridad por servicio."},
            {"id": "8.22", "title": "Segregación de redes",
             "description": "Segmentación de redes."},
            {"id": "8.23", "title": "Filtrado web",
             "description": "Control de acceso a sitios web."},
            {"id": "8.24", "title": "Criptografía",
             "description": "Normas para uso de criptografía."},
            {"id": "8.25", "title": "Ciclo de vida de desarrollo seguro",
             "description": "Desarrollo seguro de software."},
            {"id": "8.26", "title": "Requisitos de seguridad",
             "description": "Requisitos en desarrollo de aplicaciones."},
            {"id": "8.27", "title": "Arquitectura segura",
             "description": "Principios de ingeniería segura."},
            {"id": "8.28", "title": "Codificación segura",
             "description": "Principios de codificación segura."},
            {"id": "8.29", "title": "Pruebas de seguridad",
             "description": "Procesos de pruebas de seguridad."},
            {"id": "8.30", "title": "Desarrollo externalizado",
             "description": "Supervisión de desarrollo subcontratado."},
            {"id": "8.31", "title": "Separación de entornos",
             "description": "Separación entre desarrollo y producción."},
            {"id": "8.32", "title": "Gestión de cambios",
             "description": "Procedimientos de gestión de cambios."},
            {"id": "8.33", "title": "Información de pruebas",
             "description": "Protección de datos de prueba."},
            {"id": "8.34", "title": "Protección durante auditorías",
             "description": "Planificación de pruebas de auditoría."},
        ]
        
        all_controls = organizational_controls + people_controls + physical_controls + technological_controls
        
        for c in all_controls:
            # Determinar categoría
            if c["id"].startswith("5"):
                category = "organizational"
            elif c["id"].startswith("6"):
                category = "people"
            elif c["id"].startswith("7"):
                category = "physical"
            else:
                category = "technological"
                
            controls.append({
                **c,
                "category": category,
                "clause_reference": f"Cláusula {c['id'][0]}",
                "attributes": {
                    "security_domain": self._get_security_domain(c["id"]),
                    "implementation_priority": self._get_priority(c["id"])
                }
            })
        
        return controls
    
    def _get_security_domain(self, control_id: str) -> str:
        """Determina el dominio de seguridad del control"""
        domains = {
            "5": "governance",
            "6": "human_resources",
            "7": "physical_security",
            "8": "technical_security"
        }
        return domains.get(control_id[0], "general")
    
    def _get_priority(self, control_id: str) -> str:
        """Determina la prioridad de implementación"""
        high_priority = ["5.1", "5.2", "5.15", "5.16", "5.17", "5.18", "8.7", "8.8", "8.13"]
        medium_priority = ["5.3", "5.4", "5.9", "5.10", "5.12", "5.24"]
        
        if control_id in high_priority:
            return "high"
        elif control_id in medium_priority:
            return "medium"
        return "low"
    
    def _extract_requirements(self) -> List[Dict]:
        """Extrae los requisitos principales de la norma"""
        requirements = [
            {
                "clause": "4",
                "title": "Contexto de la organización",
                "requirements": [
                    "4.1 Comprender la organización y su contexto",
                    "4.2 Comprender las necesidades de las partes interesadas",
                    "4.3 Definir el alcance del SGSI",
                    "4.4 Sistema de gestión de seguridad de la información"
                ]
            },
            {
                "clause": "5",
                "title": "Liderazgo",
                "requirements": [
                    "5.1 Liderazgo y compromiso",
                    "5.2 Política de seguridad de la información",
                    "5.3 Funciones, responsabilidades y autoridades"
                ]
            },
            {
                "clause": "6",
                "title": "Planificación",
                "requirements": [
                    "6.1 Acciones para abordar riesgos",
                    "6.1.2 Evaluación de riesgos",
                    "6.1.3 Tratamiento de riesgos",
                    "6.2 Objetivos de seguridad y planificación"
                ]
            },
            {
                "clause": "7",
                "title": "Soporte",
                "requirements": [
                    "7.1 Recursos",
                    "7.2 Competencia",
                    "7.3 Concienciación",
                    "7.4 Comunicación",
                    "7.5 Información documentada"
                ]
            },
            {
                "clause": "8",
                "title": "Operación",
                "requirements": [
                    "8.1 Planificación y control operacional",
                    "8.2 Evaluación de riesgos",
                    "8.3 Tratamiento de riesgos"
                ]
            },
            {
                "clause": "9",
                "title": "Evaluación del desempeño",
                "requirements": [
                    "9.1 Monitoreo, medición, análisis",
                    "9.2 Auditoría interna",
                    "9.3 Revisión por la dirección"
                ]
            },
            {
                "clause": "10",
                "title": "Mejora",
                "requirements": [
                    "10.1 Mejora continua",
                    "10.2 No conformidad y acción correctiva"
                ]
            }
        ]
        return requirements