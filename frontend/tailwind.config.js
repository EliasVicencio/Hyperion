/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        hyperion: {
          dark: '#020617',
          card: '#0b111e',
          accent: '#3b82f6',
          purple: '#a855f7',
          border: '#1e293b'
        }
      }
    },
  },
  plugins: [],
}