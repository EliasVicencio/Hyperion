import streamlit as st
import requests
import time
import os

# 1. Configuración de la página
st.set_page_config(page_title="Proyecto Hyperion", page_icon="🚀")

# 2. Obtener la URL del backend desde las variables de entorno de Docker
# Si no existe, usa localhost por defecto para pruebas locales
BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000")

st.title("🛡️ Sistema Hyperion")
st.subheader("Panel de Control del Proyecto")

# 3. Sidebar para navegación
menu = ["Inicio", "Estado del Sistema", "Consultar Datos", "Prueba de Latencia"]
choice = st.sidebar.selectbox("Menú de Navegación", menu)

if choice == "Inicio":
    st.write("Bienvenido al sistema de gestión de base de datos Hyperion.")
    st.info("Utilice el menú lateral para navegar por las distintas secciones.")

elif choice == "Estado del Sistema":
    st.write("### Verificando conexión con el Backend...")
    
    try:
        # Intentamos conectar con la ruta /health que creamos en el backend
        response = requests.get(f"{BACKEND_URL}/health", timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            st.success(f"✅ Backend Conectado: {data.get('status')}")
            st.json(data)
        else:
            st.error(f"❌ El Backend respondió con error: {response.status_code}")
            
    except requests.exceptions.ConnectionError:
        st.error("❌ No se pudo establecer conexión con el Backend.")
        st.warning(f"Dirección intentada: {BACKEND_URL}")

elif choice == "Consultar Datos":
    st.write("### Consulta de Antecedentes")
    # Aquí puedes agregar formularios para insertar o consultar datos
    nombre = st.text_input("Ingrese nombre para buscar:")
    if st.button("Buscar"):
        st.write(f"Buscando a {nombre} en la base de datos PostgreSQL...")
        # Aquí harías un requests.get() a tu API

# Sección de "Prueba de Latencia":
elif choice == "Prueba de Latencia":
    st.header("⏱️ Monitor de Latencia Hyperion")
    st.write("Medición de respuesta: **Frontend ↔ Backend ↔ PostgreSQL**")

    # Botón para disparar la prueba
    if st.button("Ejecutar Test de Velocidad"):
        with st.spinner('Midiendo tiempos...'):
            try:
                # 1. Medimos latencia de red (Frontend -> Backend)
                t1 = time.time()
                res_back = requests.get(f"{BACKEND_URL}/health")
                t2 = time.time()
                latencia_red = (t2 - t1) * 1000

                # 2. Medimos latencia de base de datos (Backend -> DB)
                res_db = requests.get(f"{BACKEND_URL}/latencia-db")
                datos_db = res_db.json()
                latencia_db = datos_db.get("latencia_ms", 0)

                # Mostramos los resultados en columnas
                col1, col2 = st.columns(2)
                col1.metric("Latencia Red", f"{latencia_red:.2f} ms", delta_color="inverse")
                col2.metric("Latencia DB (Postgres)", f"{latencia_db:.2f} ms", delta_color="inverse")

                # Semáforo de estado
                if latencia_db < 50:
                    st.success("🟢 Rendimiento Óptimo: PostgreSQL está respondiendo instantáneamente.")
                else:
                    st.warning("🟡 Rendimiento Moderado: Revisa la carga de los contenedores.")

            except Exception as e:
                st.error(f"Error en la prueba: {e}")

    st.divider()
    st.caption("Contexto Sprint: Comparativa de rendimiento tras migración desde MySQL.")