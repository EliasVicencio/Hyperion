/** @type {import('tailwindcss').Config} */
export default {
  darkMode: 'class', // 👈 ¡ESTO ES CRUCIAL! Le dice a Tailwind que escuche la clase 'dark' que pone tu botón
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // Creamos una paleta semántica que use variantes automáticas
        hyperion: {
          dark: '#020617',
          card: '#0b111e',
          accent: '#3b82f6',
          purple: '#a855f7',
          border: '#1e293b',
          
          // ☀️ NUEVO: Agregamos variantes claras para que las uses cuando el modo oscuro esté apagado
          lightBg: '#f8fafc',    // Gris muy claro (slate-50) para el fondo general
          lightCard: '#ffffff',  // Blanco puro para las tarjetas del sistema
          lightBorder: '#e2e8f0' // Gris suave (slate-200) para los bordes limpios
        }
      }
    },
  },
  plugins: [],
}