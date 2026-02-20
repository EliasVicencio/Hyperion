import streamlit as st
import requests
import pandas as pd
import time

# 1. Configuración visual de Hyperion
st.set_page_config(
    page_title="Hyperion: Live Monitoring", 
    page_icon="👁️", 
    layout="wide"
)

# Estilo personalizado para que se vea como una herramienta de seguridad
st.markdown("""
    <style>
    .main { background-color: #0e1117; }
    .stMetric { 
        background-color: #1f2937; 
        padding: 15px; 
        border-radius: 10px; 
        border: 1px solid #374151; 
    }
    </style>
    """, unsafe_allow_html=True)

st.title("👁️ Hyperion: Central de Vigilancia")
st.write("Monitoreo de infraestructura en tiempo real")

# 2. Inicialización del historial de datos
# Guardamos los puntos para que la gráfica tenga movimiento
if 'history' not in st.session_state:
    st.session_state.history = pd.DataFrame(columns=['CPU', 'RAM'])

# 3. Espacios reservados (Contenedores)
# Esto evita que la pantalla parpadee al actualizarse
metrics_placeholder = st.empty()
chart_placeholder = st.empty()

# 4. Bucle infinito de monitoreo
while True:
    try:
        # Llamada al Backend (usando el nombre del servicio en Docker)
        response = requests.get("http://backend:8000/status", timeout=2)
        data = response.json()
        
        # Verificamos que el backend nos mandó las llaves correctas
        if "cpu" in data:
            # --- SECCIÓN DE MÉTRICAS (Tarjetas) ---
            with metrics_placeholder.container():
                col1, col2, col3 = st.columns(3)
                
                # Usamos las llaves limpias: cpu, ram, disk
                col1.metric("Uso de CPU", f"{data['cpu']}%")
                col2.metric("Memoria RAM", f"{data['ram']}%")
                col3.metric("Espacio en Disco", f"{data['disk']}%")

            # --- SECCIÓN DE GRÁFICA (Historial) ---
            # Creamos el nuevo punto con los datos actuales
            new_data = pd.DataFrame({
                'CPU': [data['cpu']], 
                'RAM': [data['ram']]
            })
            
            # Actualizamos el historial (mantenemos los últimos 30 puntos)
            st.session_state.history = pd.concat(
                [st.session_state.history, new_data], 
                ignore_index=True
            ).tail(30)
            
            with chart_placeholder.container():
                st.subheader("📈 Rendimiento en Vivo")
                st.line_chart(st.session_state.history)
                
        else:
            # Si el backend manda 'cpu_usage' en lugar de 'cpu', avisamos aquí
            st.warning(f"⚠️ Error de formato en la API. Recibido: {data}")
            
    except Exception as e:
        st.error(f"🛰️ Buscando conexión con la API de Hyperion... ({e})")
    
    # Esperar 2 segundos antes de la siguiente actualización
    time.sleep(2)