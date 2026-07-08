import React, { useState, useEffect, lazy, Suspense } from 'react';
import Sidebar from './components/Sidebar';
import Dashboard from './pages/Dashboard';
import Operadores from './pages/Operadores';
import Vigilancia from './pages/Vigilancia';
import Gobernanza from './pages/Gobernanza';
import ActivosRiesgos from './pages/ActivosRiesgos';
import Logs from './pages/Logs';
import Login from './pages/Login';
import ConfiguracionFlotante from './components/ConfiguracionFlotante';
import { AnimatePresence, motion } from 'framer-motion';
import { getToken } from './api';

const Academia = lazy(() => import('./pages/Academia'));

export default function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(() => {
    return !!getToken();
  });

  const [page, setPage] = useState('Analiticas');
  const [isConfigOpen, setIsConfigOpen] = useState(false);

  const [currentUser, setCurrentUser] = useState(() => {
    const saved = localStorage.getItem('hyperion_user');
    try {
      return saved ? JSON.parse(saved) : null;
    } catch (e) {
      console.error("Error leyendo hyperion_user:", e);
      return null;
    }
  });

  useEffect(() => {
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme === 'dark' || (!savedTheme && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  }, []);

  const handleLoginSuccess = (userData) => {
    localStorage.setItem('hyperion_user', JSON.stringify(userData));
    setCurrentUser(userData);
    setIsAuthenticated(true);
  };

  const handleLogout = () => {
    localStorage.removeItem('hyperion_token');
    localStorage.removeItem('hyperion_auth');
    localStorage.removeItem('hyperion_user');
    setCurrentUser(null);
    setIsAuthenticated(false);
  };

  if (!isAuthenticated) {
    return <Login onLoginSuccess={handleLoginSuccess} />;
  }

  const renderPage = (targetPage) => {
    const key = targetPage
      .toLowerCase()
      .normalize("NFD")
      .replace(/[\u0300-\u036f]/g, "")
      .trim();

    const views = {
      'analiticas': <Dashboard />,
      'dashboard': <Dashboard />,
      'vigilancia': <Vigilancia />,
      'operadores': <Operadores />,
      'gestion de usuarios': <Operadores />,
      'gobernanza': <Gobernanza />,
      'activos y riesgos': <ActivosRiesgos />, // ⬅️ ENRUTADO PARA MENU 
      'activosriesgos': <ActivosRiesgos />,    // ⬅️ RESPALDO DE SEGURIDAD POR KEY
      'logs': <Logs />,
      'logs de auditoria': <Logs />,
      'academia': (
        <Suspense fallback={
          <div className="h-[60vh] flex items-center justify-center">
            <p className="dark:text-slate-500 text-slate-400 italic">Cargando Academia...</p>
          </div>
        }>
          <Academia user={currentUser} />
        </Suspense>
      ),
      'academia compliance': (
        <Suspense fallback={
          <div className="h-[60vh] flex items-center justify-center">
            <p className="dark:text-slate-500 text-slate-400 italic">Cargando Academia...</p>
          </div>
        }>
          <Academia user={currentUser} />
        </Suspense>
      )
    };

    return views[key] || (
      <div className="h-[60vh] flex items-center justify-center border border-dashed dark:border-slate-800 border-slate-300 rounded-3xl">
        <p className="dark:text-slate-500 text-slate-400 italic">Módulo {targetPage} en fase de despliegue...</p>
      </div>
    );
  };

  const normalizedPageKey = page
    .toLowerCase()
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .trim();

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-slate-950 text-slate-800 dark:text-slate-200 flex font-sans selection:bg-blue-500/30 transition-colors duration-300">
      
      <Sidebar 
        currentPage={page} 
        setPage={setPage} 
        onLogout={handleLogout} 
        onOpenConfig={() => setIsConfigOpen(true)} 
        isConfigOpen={isConfigOpen}
      />
      
      <main className="flex-1 ml-64 min-h-screen relative">
        <div className="p-8 max-w-7xl mx-auto">
          <AnimatePresence mode="wait">
            <motion.div
              key={normalizedPageKey}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              transition={{ duration: 0.2 }}
            >
              {renderPage(page)}
            </motion.div>
          </AnimatePresence>
        </div>
      </main>

      <ConfiguracionFlotante 
        isOpen={isConfigOpen} 
        onClose={() => setIsConfigOpen(false)} 
      />
    </div>
  );
}