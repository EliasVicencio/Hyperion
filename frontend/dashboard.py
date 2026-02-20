import streamlit as st
import requests

st.set_page_config(page_title="Hyperion Eye", layout="wide")
st.title("👁️ Hyperion: Sistema de Vigilancia Central")

# Ejemplo de métrica de salud real
health = requests.get("http://backend:8000/status").json()
st.metric("Estado del Sistema", health["status"], delta=health["latency"])