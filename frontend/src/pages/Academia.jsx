import React, { useState, useEffect } from 'react';
import { supabase } from '../supabase'; 
import { BookOpen, Clock, CheckCircle2, AlertTriangle, HelpCircle, ChevronRight, Download, Shield, Cpu } from 'lucide-react';

export default function Academia({ user }) {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [downloading, setDownloading] = useState(false);

  // 🌟 NUEVO: Estado para elegir el trayecto (ISO o NIST)
  const [activeFramework, setActiveFramework] = useState('ISO'); 

  // Datos provenientes de la BD
  const [domains, setDomains] = useState([]);
  const [lessons, setLessons] = useState([]);
  const [checkpoints, setCheckpoints] = useState([]);

  // Navegación
  const [selectedDomain, setSelectedDomain] = useState(null);
  const [selectedLesson, setSelectedLesson] = useState(null);
  const [selectedAnswer, setSelectedAnswer] = useState(null);
  const [quizFeedback, setQuizFeedback] = useState(null); 

  const [userProgress, setUserProgress] = useState(() => {
    const saved = localStorage.getItem('hyperion_academy_progress');
    try { return saved ? JSON.parse(saved) : {}; } catch { return {}; }
  });

  // 1. CARGA DE DATOS FILTRADA POR FRAMEWORK
  useEffect(() => {
    async function fetchAcademyData() {
      try {
        setLoading(true);
        setError(null);

        // Elegimos la tabla de dominios según el trayecto
        const domainTable = activeFramework === 'ISO' ? 'iso_domains' : 'nist_families';

        const [resDomains, resLessons, resCheckpoints] = await Promise.all([
          supabase.from(domainTable).select('*').order('id', { ascending: true }),
          supabase.from('academy_lessons').select('*').eq('framework', activeFramework).order('sort_order', { ascending: true }),
          supabase.from('academy_checkpoints').select('*')
        ]);

        if (resDomains.error) throw resDomains.error;
        if (resLessons.error) throw resLessons.error;

        setDomains(resDomains.data || []);
        setLessons(resLessons.data || []);
        setCheckpoints(resCheckpoints.data || []);

        // Preseleccionar primero por defecto
        if (resDomains.data?.length > 0) {
          const firstDom = resDomains.data[0].id;
          setSelectedDomain(firstDom);
          const firstLess = resLessons.data.find(l => l.domain_id === firstDom);
          setSelectedLesson(firstLess || null);
        }

      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    }
    fetchAcademyData();
  }, [activeFramework]); // 🔄 Se recarga cada vez que cambias de ISO a NIST

  useEffect(() => {
    localStorage.setItem('hyperion_academy_progress', JSON.stringify(userProgress));
  }, [userProgress]);

  // Lógica de filtrado y Quiz
  const currentLessons = lessons.filter(l => l.domain_id === selectedDomain);
  const currentCheckpoint = checkpoints.find(cp => cp.lesson_id === selectedLesson?.id);
  
  const quizOptions = currentCheckpoint ? (Array.isArray(currentCheckpoint.options) ? currentCheckpoint.options : JSON.parse(currentCheckpoint.options || "[]")) : [];

  const handleVerifyAnswer = async () => {
    if (!selectedAnswer || !currentCheckpoint) return;
    if (String(selectedAnswer).toUpperCase() === String(currentCheckpoint.correct_option_id).toUpperCase()) {
      setQuizFeedback({ success: true, message: "¡Control asimilado! Firma de cumplimiento registrada." });
      setUserProgress(prev => ({ ...prev, [selectedLesson.id]: true }));
    } else {
      setQuizFeedback({ success: false, message: "Respuesta incorrecta. Revisa los controles técnicos." });
    }
  };

  if (loading) return <div className="h-[70vh] flex flex-col items-center justify-center space-y-4"><div className="w-12 h-12 border-4 border-blue-500 border-t-transparent rounded-full animate-spin"></div><p className="text-slate-400 font-mono text-xs">SINCRONIZANDO_MARCO_{activeFramework}...</p></div>;

  return (
    <div className="space-y-8 text-slate-800 dark:text-slate-300">
      
      {/* CABECERA CON SELECTOR DE FRAMEWORK */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
        <div>
          <div className="flex items-center space-x-3 mb-2">
            <div className={`p-2.5 rounded-2xl border ${activeFramework === 'ISO' ? 'bg-blue-500/10 text-blue-500 border-blue-500/20' : 'bg-cyan-500/10 text-cyan-500 border-cyan-500/20'}`}>
              <BookOpen className="w-6 h-6" />
            </div>
            <h1 className="text-2xl font-bold tracking-tight text-white">Academia Compliance & Hardening</h1>
          </div>
          <p className="text-slate-400 text-sm">Entrenamiento basado en {activeFramework === 'ISO' ? 'ISO/IEC 27001:2022' : 'NIST SP 800-53 Rev. 5'}</p>
        </div>

        {/* 🌟 SELECTOR DE TRAYECTO CYBERPUNK */}
        <div className="flex bg-slate-900/50 p-1 border border-slate-800 rounded-2xl self-start shadow-inner">
          <button 
            onClick={() => setActiveFramework('ISO')}
            className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold transition-all ${activeFramework === 'ISO' ? 'bg-blue-600 text-white' : 'text-slate-500 hover:text-slate-300'}`}
          >
            <Shield size={14} /> ISO 27001
          </button>
          <button 
            onClick={() => setActiveFramework('NIST')}
            className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold transition-all ${activeFramework === 'NIST' ? 'bg-cyan-600 text-white' : 'text-slate-500 hover:text-slate-300'}`}
          >
            <Cpu size={14} /> NIST 800-53
          </button>
        </div>
      </div>

      {/* DASHBOARD DE ESTADÍSTICAS (Adaptado al color del Framework) */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        <div className="p-6 bg-slate-900/40 border border-slate-800/80 rounded-2xl">
          <p className="text-[10px] font-bold uppercase tracking-widest text-slate-500 mb-1">Estatus del Trayecto {activeFramework}</p>
          <p className="text-3xl font-bold text-white">{globalCompletionPercentage}%</p>
          <div className="w-full bg-slate-800 h-1.5 rounded-full mt-4 overflow-hidden">
            <div className={`h-full transition-all duration-700 ${activeFramework === 'ISO' ? 'bg-blue-500' : 'bg-cyan-500'}`} style={{ width: `${globalCompletionPercentage}%` }}></div>
          </div>
        </div>
        {/* ... (Las otras dos cards se mantienen igual) */}
      </div>

      {/* ÁREA DE TRABAJO PRINCIPAL */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
        {/* COLUMNA IZQUIERDA: INDEXACIÓN */}
        <div className="lg:col-span-4 space-y-4">
          <div className="p-4 bg-slate-900/60 border border-slate-800/80 rounded-2xl shadow-sm">
            <h3 className="text-[10px] font-bold text-slate-500 uppercase mb-3 px-1">
              {activeFramework === 'ISO' ? 'Secciones Anexo A' : 'Familias de Control NIST'}
            </h3>
            <div className="flex flex-wrap gap-2">
              {domains.map((dom) => (
                <button
                  key={dom.id}
                  onClick={() => handleDomainChange(dom.id)}
                  className={`px-3 py-1.5 text-xs font-bold rounded-xl border transition-all ${selectedDomain === dom.id
                    ? (activeFramework === 'ISO' ? 'bg-blue-500/10 text-blue-400 border-blue-500/40' : 'bg-cyan-500/10 text-cyan-400 border-cyan-500/40')
                    : 'bg-slate-900 border-slate-800 text-slate-500'}`}
                >
                  {dom.id}
                </button>
              ))}
            </div>
          </div>

          {/* LISTADO DE LECCIONES */}
          <div className="space-y-2">
            {currentLessons.map((lesson) => {
              const isActive = selectedLesson?.id === lesson.id;
              const isCompleted = !!userProgress[lesson.id];
              return (
                <button
                  key={lesson.id}
                  onClick={() => handleLessonChange(lesson)}
                  className={`w-full p-4 rounded-2xl text-left border flex items-center justify-between transition-all ${isActive
                    ? (activeFramework === 'ISO' ? 'bg-blue-600 border-blue-500 shadow-blue-500/10' : 'bg-cyan-600 border-cyan-500 shadow-cyan-500/10') + ' text-white shadow-lg'
                    : 'bg-slate-900/40 border-slate-800/80'}`}
                >
                  <div className="space-y-1">
                    <h4 className="text-sm font-semibold">{lesson.title}</h4>
                    <div className="text-[10px] opacity-60 font-mono">{lesson.mapped_controls?.join(', ')}</div>
                  </div>
                  {isCompleted && <CheckCircle2 size={16} />}
                </button>
              );
            })}
          </div>
        </div>

        {/* COLUMNA DERECHA: CONTENIDO */}
        <div className="lg:col-span-8 space-y-6">
          {selectedLesson && (
            <div className="p-8 bg-slate-900/30 border border-slate-800/80 rounded-3xl space-y-6">
              <span className={`text-[10px] font-bold uppercase tracking-widest ${activeFramework === 'ISO' ? 'text-blue-500' : 'text-cyan-500'}`}>
                {activeFramework} Framework Compliance
              </span>
              <h2 className="text-2xl font-bold text-white">{selectedLesson.title}</h2>
              <div className="prose prose-invert prose-sm max-w-none text-slate-400 whitespace-pre-wrap">
                {selectedLesson.content_markdown}
              </div>
            </div>
          )}
          
          {/* SECCIÓN DEL QUIZ (Mismo diseño, funcionalidad vinculada) */}
          {currentCheckpoint && (
             <div className="p-6 border border-purple-500/20 bg-purple-500/5 rounded-3xl space-y-5">
                <h4 className="text-xs font-bold text-purple-400 uppercase tracking-widest flex items-center gap-2">
                  <HelpCircle size={16}/> Checkpoint de Validación {activeFramework}
                </h4>
                <p className="text-sm text-white font-medium">{currentCheckpoint.question}</p>
                <div className="space-y-2">
                  {quizOptions.map((opt) => (
                    <button
                      key={opt.id}
                      onClick={() => { setSelectedAnswer(opt.id); setQuizFeedback(null); }}
                      className={`w-full p-4 rounded-xl text-left border text-xs font-medium transition-all ${selectedAnswer === opt.id ? 'bg-purple-500/20 border-purple-500 text-purple-300' : 'bg-slate-900/50 border-slate-800 text-slate-400'}`}
                    >
                      {opt.text}
                    </button>
                  ))}
                </div>
                <button onClick={handleVerifyAnswer} className="w-full py-3 bg-purple-600 text-white rounded-xl font-bold text-xs uppercase tracking-widest hover:bg-purple-500 transition-all">Verificar Conocimiento</button>
             </div>
          )}
        </div>
      </div>
    </div>
  );
}