import React, { useState } from 'react';
import Sidebar from './components/Sidebar';
import Dashboard from './pages/Dashboard';
import Operadores from './pages/Operadores';
import Vigilancia from './pages/Vigilancia';
import Gobernanza from './pages/Gobernanza';
import Logs from './pages/Logs';
import Login from './pages/Login'; // 👈 1. Importa la nueva pantalla de Login
import { AnimatePresence, motion } from 'framer-motion';

export default function App() {
  // Estado para controlar si el operador tiene acceso o no
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [page, setPage] = useState('Analiticas');

  // Si no está autenticado, renderizamos ÚNICAMENTE la pantalla de Login
  if (!isAuthenticated) {
    return <Login onLoginSuccess={() => setIsAuthenticated(true)} />;
  }

  const renderPage = () => {
    switch (page) {
      case 'Analiticas': return <Dashboard />;
      case 'Vigilancia': return <Vigilancia />;
      case 'Operadores': return <Operadores />;
      case 'Gobernanza': return <Gobernanza />;
      case 'Logs':       return <Logs />;
      default:
        return (
          <div className="h-[60vh] flex items-center justify-center border border-dashed border-slate-800 rounded-3xl">
              <p className="text-slate-500 italic">Módulo {page} en fase de despliegue...</p>
          </div>
        );
    }
  };

  return (
    <div className="min-h-screen bg-[#020617] text-slate-200 flex font-sans selection:bg-blue-500/30">
      {/* Pasamos una función para que el botón "Cerrar Sistema" funcione y bloquee la app */}
      <Sidebar currentPage={page} setPage={setPage} onLogout={() => setIsAuthenticated(false)} />
      
      <main className="flex-1 ml-64 min-h-screen relative">
        <div className="p-8 max-w-7xl mx-auto">
          <AnimatePresence mode="wait">
            <motion.div
              key={page}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              transition={{ duration: 0.2 }}
            >
              {renderPage()}
            </motion.div>
          </AnimatePresence>
        </div>
      </main>
    </div>
  );
}