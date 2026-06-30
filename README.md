# 👁️ Project Hyperion: Integrated Vigilance & Optimization

**Hyperion** es una plataforma avanzada de mando SOC, analíticas y gobernanza inmutable diseñada bajo el framework de ciberseguridad **NIST SP 800-53**. Construido mediante una arquitectura de microservicios desacoplados que garantiza velocidad, alta disponibilidad y visibilidad perimetral total en infraestructuras críticas.

---

## 🛠️ Stack Tecnológico Core
* **Frontend:** Streamlit (UI Reactiva e Inyectada con CSS customizado).
* **Backend:** FastAPI (Motor asíncrono de alto rendimiento).
* **Base de Datos:** PostgreSQL / Supabase Cluster (Pool de conexiones optimizado).
* **Mensajería:** Kafka Node (Bitácora legal inmutable y telemetría distributed logs).

---

## ⚙️ Variables de Entorno (.env)
Antes de inicializar el sistema, asegúrate de configurar un archivo `.env` en la raíz del proyecto con los siguientes parámetros:

```env
# Configuración del Backend
BACKEND_URL=[https://hyperion-pi-nine.vercel.app/](https://hyperion-pi-nine.vercel.app/)
TOTP_SECRET=JBSWY3DPEHPK3PXP

# Configuración del Entorno de Red
DOCKER_PORT_API=8000
DOCKER_PORT_UI=8501
```

## 🚀 Inicio Rápido y Pruebas Locales (Docker)
```shell
docker-compose up --build -d

> Dashboard accesible en: http://localhost:8501
> Documentación API (Swagger): http://localhost:8000/docs
```

## 📦 Despliegue sin Contenedores (Manual / Debugging)

* 1. Inicializar el Nodo Central (FastAPI)

```bash
cd backend
python -m venv venv
source venv/bin/activate  # En Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

* 2. Inicializar la Interfaz de Mando (Streamlit)

```bash
cd frontend
python -m venv venv
source venv/bin/activate  # En Windows: venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py --server.port 8501
```

## 🧪 Suite de Pruebas Locales (Testing)

El sistema cuenta con pruebas unitarias y de integración para validar la autenticación 2FA, la persistencia en base de datos y la integridad de los logs del SIEM.

### Ejecución de Pruebas Unitarias

Asegúrate de tener instalado pytest y las dependencias de desarrollo

```bash
# Ejecutar todas las pruebas del ecosistema
pytest

# Ejecutar pruebas con reporte detallado de cobertura (Coverage)
pytest --cov=backend --cov=frontend -vv
```

## Simulación de Tráfico y Ataques (Sanity Check)

Para verificar la respuesta del motor de Deep Packet Inspection (DPI) y la inyección en las bitácoras del SIEM sin tráfico real, ejecuta el script de telemetría simulada

```bash
python scripts/simulate_traffic.py --requests 100 --target http://localhost:8000
```

## 🛡️ Cumplimiento y Seguridad de la Infraestructura

* Auditoría de Red Inbound (Módulo VPN SIEM): Monitoreo perimetral activo en la pestaña del SIEM que discrimina dinámicamente el origen de las peticiones (Nodo Local SOC vía Intranet Física vs. Accesos Remotos), validando en tiempo real la firma criptográfica del túnel VPN e identificando IPs virtuales protegidas o alertas por IPs públicas no cifradas.

* Cifrado de Extremo a Extremo: Comunicación forzada mediante TLS v1.3 en ambientes de producción.

* Módulo de Autenticación: Esquema estricto de dos factores (2FA/TOTP) con tokens de sesión dinámicos que expiran automáticamente conforme a las directrices de control de accesos de la NIST.