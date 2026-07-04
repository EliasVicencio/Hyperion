import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Configuración estándar para Tailwind v3 + PostCSS
export default defineConfig({
  plugins: [react()],
})