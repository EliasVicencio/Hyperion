# 👁️ Project Hyperion: Integrated Vigilance & Optimization

**Hyperion** es una plataforma avanzada de mando SOC, analíticas y gobernanza inmutable diseñada bajo el estándar internacional de seguridad de la información **ISO/IEC 27001:2022**. Construido mediante una arquitectura de servicios desacoplados que garantiza velocidad, alta disponibilidad y visibilidad perimetral total en infraestructuras críticas.

---

## 🛠️ Stack Tecnológico Core
* **Frontend:** React / Vite (UI de Alta Fidelidad optimizada con Tailwind CSS y Lucide Icons).
* **Backend:** FastAPI (Motor asíncrono de alto rendimiento con SQLAlchemy Async).
* **Base de Datos:** PostgreSQL / Supabase Cluster (Pool de conexiones asíncronas nativas).
* **Mensajería y Logs:** Kafka Node (Bitácora legal inmutable y telemetría distributed logs).

---

## ⚙️ Variables de Entorno (.env)
Antes de inicializar el sistema, asegúrate de configurar un archivo `.env` en la raíz del proyecto con los siguientes parámetros:

```env
# Configuración del Backend y Base de Datos
DATABASE_URL=postgresql+asyncpg://user:password@your-supabase-host:5432/postgres
BACKEND_URL=[https://hyperion-pi-nine.vercel.app/](https://hyperion-pi-nine.vercel.app/)
TOTP_SECRET=JBSWY3DPEHPK3PXP

# Configuración del Entorno de Red
DOCKER_PORT_API=8000
DOCKER_PORT_UI=3000
```
## 🚀 Inicialización del Entorno y Sembrado de Datos (ISO 27001:2022)
Para desplegar y poblar la academia técnica con los 93 controles reales del Anexo A de la ISO 27001:2022 de forma asíncrona y autónoma, ejecuta los siguientes scripts en orden dentro de la carpeta del backend:

```bash
# 1. Analizar y estructurar los controles desde las fuentes oficiales JSON/PDF
python scripts/setup_iso_analyzer.py

# 2. Inyectar dinámicamente los 93 controles reales y checkpoints en Supabase
python scripts/load_iso_academy.py
```

## ⚙️ Inicio Rápido y Pruebas Locales (Docker)
```shell
docker-compose up --build -d

> Dashboard Interactivo (React): http://localhost:3000
> Documentación API (Swagger): http://localhost:8000/docs
```

## 📦 Despliegue sin Contenedores (Manual / Debugging)
* 1. Inicializar el Nodo Central (FastAPI Backend)
```bash
cd backend
python -m venv venv
source venv/bin/activate  # En Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

* 2. Inicializar la Interfaz de Mando (React Frontend)
```bash
cd frontend
npm install
npm run dev -- --port 3000
```

## 🧪 Suite de Pruebas Locales (Testing)
El sistema cuenta con pruebas unitarias y de integración para validar la autenticación 2FA, la persistencia en base de datos asíncrona y la integridad de los logs del SIEM.

Ejecución de Pruebas Unitarias
```bash
# Ejecutar todas las pruebas del ecosistema
pytest

# Ejecutar pruebas con reporte detallado de cobertura (Coverage)
pytest --cov=backend --cov=frontend -vv
```

## 🛡️ Cumplimiento y Seguridad de la Infraestructura
Compliance Hub & Academia Interactiva: Módulo de capacitación y auditoría interna que despliega los 93 controles de la ISO 27001:2022 distribuidos dinámicamente en sus 4 pilares nativos (Organizacionales A.5, Personas A.6, Físicos A.7 y Tecnológicos A.8), incluyendo checkpoints de validación operacional para los usuarios del SOC.

Auditoría de Red Inbound (Módulo VPN SIEM): Monitoreo perimetral activo en la pestaña del SIEM que discrimina dinámicamente el origen de las peticiones (Nodo Local SOC vía Intranet Física vs. Accesos Remotos), validando en tiempo real la firma criptográfica del túnel VPN e identificando IPs virtuales protegidas o alertas por IPs públicas no cifradas.

Cifrado de Extremo a Extremo: Comunicación forzada mediante TLS v1.3 en ambientes de producción y aislamiento de pool de conexiones.

Módulo de Autenticación: Esquema estricto de dos factores (2FA/TOTP) con tokens de sesión dinámicos que expiran automáticamente conforme a las directrices de control de accesos de la norma.