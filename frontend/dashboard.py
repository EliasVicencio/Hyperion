import streamlit as st
import requests
import pandas as pd
import time

st.set_page_config(page_title="Hyperion: Central de Vigilancia", layout="wide")
st.title("👁️ Hyperion: Central de Vigilancia")

placeholder = st.empty()

while True:
    try:
        response = requests.get("http://backend:8000/metrics")
        data = response.json()

        with placeholder.container():
            # Métricas principales
            col1, col2, col3 = st.columns(3)
            col1.metric("Uso de CPU", f"{data['cpu_usage']}%")
            col2.metric("Memoria RAM", f"{data['ram_usage']}%")
            col3.metric("Espacio en Disco", f"{data['disk_usage']}%")

            # Gráfico de histórico
            st.subheader("📈 Rendimiento Histórico (Base de Datos)")
            df = pd.DataFrame(data['history'])
            if not df.empty:
                st.line_chart(df.set_index('time'))

    except Exception as e:
        st.error(f"Error de conexión: {e}")
    
    time.sleep(5)