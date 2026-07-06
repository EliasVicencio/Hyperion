import React, { useState, useEffect } from 'react';
import { supabase } from '../supabase'; // Ajusta la ruta según la estructura de tu proyecto
import { BookOpen, Clock, CheckCircle2, AlertTriangle, HelpCircle, ChevronRight, Download, Shield, Cpu } from 'lucide-react';

export default function Academia({ user }) {
  // Estados de carga e interfaz
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [downloading, setDownloading] = useState(false);

  // 🌟 Estado de control del Framework activo
  const [activeFramework, setActiveFramework] = useState('ISO'); 

  // Estados de datos provenientes de la BD
  const [domains, setDomains] = useState([]);
  const [lessons, setLessons] = useState([]);
  const [checkpoints, setCheckpoints] = useState([]);

  // Estados de navegación e interacción del usuario
  const [selectedDomain, setSelectedDomain] = useState(null);
  const [selectedLesson, setSelectedLesson] = useState(null);
  const [selectedAnswer, setSelectedAnswer] = useState(null);
  const [quizFeedback, setQuizFeedback] = useState(null); 

  // Estado de progreso local del usuario
  const [userProgress, setUserProgress] = useState(() => {
    const saved = localStorage.getItem('hyperion_academy_progress');
    if (saved && saved !== "undefined" && saved !== "null") {
      try {
        return JSON.parse(saved);
      } catch (e) {
        console.error("Error parseando progreso inicial:", e);
        return {};
      }
    }
    return {};
  });

  // 1. CARGA DINÁMICA SEGÚN EL FRAMEWORK SELECCIONADO
  useEffect(() => {
    async function fetchAcademyData() {
      try {
        setLoading(true);
        setError(null);

        // Elegimos la tabla de dominios/familias dependiendo del framework activo
        const domainTable = activeFramework === 'ISO' ? 'iso_domains' : 'nist_families';

        // Traer de forma paralela los datos filtrando lecciones por framework técnico
        const [resDomains, resLessons, resCheckpoints] = await Promise.all([
          supabase.from(domainTable).select('*').order('id', { ascending: true }),
          supabase.from('academy_lessons').select('*').eq('framework', activeFramework).order('sort_order', { ascending: true }),
          supabase.from('academy_checkpoints').select('*')
        ]);

        if (resDomains.error) throw resDomains.error;
        if (resLessons.error) throw resLessons.error;
        if (resCheckpoints.error) throw resCheckpoints.error;

        const dataDomains = resDomains.data || [];
        const dataLessons = resLessons.data || [];
        const dataCheckpoints = resCheckpoints.data || [];

        setDomains(dataDomains);
        setLessons(dataLessons);
        setCheckpoints(dataCheckpoints);

        // Preseleccionar el primer pilar disponible del framework y su primera lección
        if (dataDomains.length > 0) {
          const firstDom = dataDomains[0].id;
          setSelectedDomain(firstDom);

          const firstLess = dataLessons.find(l =>
            l.domain_id?.trim().toUpperCase() === firstDom.trim().toUpperCase()
          );
          if (firstLess) {
            setSelectedLesson(firstLess);
          } else {
            setSelectedLesson(null);
          }
        } else {
          setSelectedDomain(null);
          setSelectedLesson(null);
        }

      } catch (err) {
        console.error("🚨 Error inicializando el modulo de Academia:", err.message);
        setError(err.message);
      } finally {
        setLoading(false);
      }
    }

    fetchAcademyData();
  }, [activeFramework]); // 🔄 Se dispara automáticamente al alternar ISO <-> NIST

  // Guardar progreso en LocalStorage
  useEffect(() => {
    localStorage.setItem('hyperion_academy_progress', JSON.stringify(userProgress));
  }, [userProgress]);

  // 2. FILTRADO EN CALIENTE DE LECCIONES POR DOMINIO SELECCIONADO
  const currentLessons = lessons.filter(
    lesson => lesson.domain_id?.trim().toUpperCase() === selectedDomain?.trim().toUpperCase()
  );

  // Buscar el quiz del control actual
  const currentCheckpoint = checkpoints.find(
    cp => cp.lesson_id === selectedLesson?.id
  );

  // 3. PROCESAMIENTO SEGURO DE LAS OPCIONES DEL QUIZ
  const quizOptions = (() => {
    if (!currentCheckpoint) return [];
    if (Array.isArray(currentCheckpoint.options)) return currentCheckpoint.options;
    if (typeof currentCheckpoint.options === 'string') {
      try {
        return JSON.parse(currentCheckpoint.options);
      } catch (e) {
        console.error("Error parseando opciones:", e);
        return [];
      }
    }
    return [];
  })();

  // 4. MANEJADORES DE ACCIONES
  const handleDomainChange = (domainId) => {
    setSelectedDomain(domainId);
    setQuizFeedback(null);
    setSelectedAnswer(null);

    const firstLessonOfDomain = lessons.find(l =>
      l.domain_id?.trim().toUpperCase() === domainId.trim().toUpperCase()
    );
    setSelectedLesson(firstLessonOfDomain || null);
  };

  const handleLessonChange = (lesson) => {
    setSelectedLesson(lesson);
    setQuizFeedback(null);
    setSelectedAnswer(null);
  };

  const handleVerifyAnswer = async () => {
    if (!selectedAnswer || !currentCheckpoint) return;

    const answerClean = String(selectedAnswer).trim().toUpperCase();
    const correctClean = String(currentCheckpoint.correct_option_id).trim().toUpperCase();

    if (answerClean === correctClean) {
      setQuizFeedback({
        success: true,
        message: `¡Excelente! Respuesta correcta. El control de ${activeFramework} ha sido asimilado correctamente.`
      });
      
      setUserProgress(prev => {
        const updated = { ...prev, [selectedLesson.id]: true };
        localStorage.setItem('hyperion_academy_progress', JSON.stringify(updated));
        return updated;
      });

      // Persistencia opcional en base de datos si cuentas con la tabla de seguimiento
      try {
        const emailOperador = user?.email || "elias.vicencio@hyperion.com";
        await supabase
          .from('user_lessons_progress') 
          .upsert({ 
            user_email: emailOperador, 
            lesson_id: selectedLesson.id, 
            completed: true,
            framework: activeFramework,
            updated_at: new Date().toISOString()
          }, { onConflict: 'user_email,lesson_id' });
      } catch (backendErr) {
        console.warn("Mapeo de progreso en BD no disponible:", backendErr.message);
      }
    } else {
      setQuizFeedback({
        success: false,
        message: `Respuesta incorrecta. Repasa las directrices del control técnico de la ${activeFramework} e inténtalo de nuevo.`
      });
    }
  };

  const handleDownloadDocument = async () => {
    if (!selectedLesson) return;
    try {
      setDownloading(true);
      const url = activeFramework === 'ISO' 
        ? 'https://www.iso.org/standard/27001' 
        : 'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final';
      window.open(url, '_blank');
    } catch (err) {
      console.warn("Falla al abrir el sitio oficial.", err.message);
    } finally {
      setTimeout(() => setDownloading(false), 600);
    }
  };

  // 5. CÁLCULO DE MÉTRICAS OPERATIVAS (Métricas unificadas)
  const totalLessonsCount = lessons.length || 1;
  const completedCount = Object.keys(userProgress).filter(id => userProgress[id] && lessons.some(l => l.id === id)).length;
  const globalCompletionPercentage = Math.round((completedCount / totalLessonsCount) * 100);
  const totalHoursDedicated = (completedCount * 15) / 60;

  if (loading) {
    return (
      <div className="h-[70vh] flex flex-col items-center justify-center space-y-4">
        <div className={`w-12 h-12 border-4 ${activeFramework === 'ISO' ? 'border-blue-500' : 'border-cyan-500'} border-t-transparent rounded-full animate-spin`}></div>
        <p className="text-slate-500 dark:text-slate-400 font-medium animate-pulse">Sincronizando Controles {activeFramework}...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="h-[60vh] flex flex-col items-center justify-center p-6 border border-red-500/20 bg-red-500/5 rounded-3xl max-w-xl mx-auto text-center">
        <AlertTriangle className="w-12 h-12 text-red-500 mb-3" />
        <h3 className="text-lg font-bold text-red-400 mb-1">Falla de Enlace con Supabase</h3>
        <p className="text-slate-400 text-sm mb-4">{error}</p>
        <button
          onClick={() => window.location.reload()}
          className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white font-medium rounded-xl text-xs transition-all"
        >
          Reintentar Conexión
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-8 text-slate-800 dark:text-slate-300">
      {/* CABECERA Y TITULARES (Con Switcher integrado arriba a la derecha) */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-3 mb-2">
            <div className={`p-2.5 ${activeFramework === 'ISO' ? 'bg-blue-500/10 text-blue-600 dark:text-blue-500 border-blue-500/20' : 'bg-cyan-500/10 text-cyan-600 dark:text-cyan-500 border-cyan-500/20'} rounded-2xl border`}>
              <BookOpen className="w-6 h-6" />
            </div>
            <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-white">Compliance Hub & Academia {activeFramework}</h1>
          </div>
          <p className="text-slate-500 dark:text-slate-400 text-sm">
            Centro de capacitación técnica bajo las directrices del estándar <span className={`${activeFramework === 'ISO' ? 'text-blue-600 dark:text-blue-400' : 'text-cyan-600 dark:text-cyan-400'} font-semibold`}>{activeFramework === 'ISO' ? 'ISO/IEC 27001:2022' : 'NIST SP 800-53 Rev. 5'}</span>.
          </p>
        </div>

        {/* 🌟 CONTROLLER DEL BREADCRUMB / SWITCHER TÉCNICO */}
        <div className="flex bg-slate-100 dark:bg-slate-900/80 p-1 border border-slate-200 dark:border-slate-800/80 rounded-2xl self-start shadow-sm">
          <button 
            onClick={() => setActiveFramework('ISO')}
            className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold transition-all ${activeFramework === 'ISO' ? 'bg-blue-600 text-white shadow-md shadow-blue-600/10' : 'text-slate-500 hover:text-slate-800 dark:hover:text-slate-300'}`}
          >
            <Shield size={13} /> ISO 27001
          </button>
          <button 
            onClick={() => setActiveFramework('NIST')}
            className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold transition-all ${activeFramework === 'NIST' ? 'bg-cyan-600 text-white shadow-md shadow-cyan-600/10' : 'text-slate-500 hover:text-slate-800 dark:hover:text-slate-300'}`}
          >
            <Cpu size={13} /> NIST 800-53
          </button>
        </div>
      </div>

      {/* DASHBOARD DE ESTADÍSTICAS */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        <div className="p-6 bg-white dark:bg-slate-900/40 border border-slate-200 dark:border-slate-800/80 rounded-2xl shadow-sm">
          <p className="text-xs font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500 mb-1">Progreso en Auditoría ({activeFramework})</p>
          <p className="text-3xl font-bold text-slate-800 dark:text-slate-100">{globalCompletionPercentage}%</p>
          <div className="w-full bg-slate-100 dark:bg-slate-800 h-2 rounded-full mt-4 overflow-hidden">
            <div className={`h-full transition-all duration-500 ${activeFramework === 'ISO' ? 'bg-blue-500' : 'bg-cyan-500'}`} style={{ width: `${globalCompletionPercentage}%` }}></div>
          </div>
        </div>

        <div className="p-6 bg-white dark:bg-slate-900/40 border border-slate-200 dark:border-slate-800/80 rounded-2xl shadow-sm">
          <p className="text-xs font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500 mb-1">Tiempo de Estudio</p>
          <p className="text-3xl font-bold text-slate-800 dark:text-slate-100">{totalHoursDedicated.toFixed(1)} <span className="text-sm text-slate-400 dark:text-slate-500 font-normal">/ 15 HRS</span></p>
          <p className="text-xs text-slate-400 dark:text-slate-500 mt-3 flex items-center gap-1"><Clock className="w-3.5 h-3.5" /> Calculado dinámicamente por módulos superados.</p>
        </div>

        <div className="p-6 bg-white dark:bg-slate-900/40 border border-slate-200 dark:border-slate-800/80 rounded-2xl flex items-center justify-between shadow-sm">
          <div>
            <p className="text-xs font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500 mb-1">Controles Validados</p>
            <p className="text-3xl font-bold text-slate-800 dark:text-slate-100">{completedCount} <span className="text-sm text-slate-400 dark:text-slate-500 font-normal">CONTROLES</span></p>
          </div>
          <div className={`p-3.5 rounded-2xl ${completedCount > 0 ? (activeFramework === 'ISO' ? 'bg-emerald-50 dark:bg-emerald-500/10 text-emerald-600 dark:text-emerald-500' : 'bg-cyan-50 dark:bg-cyan-500/10 text-cyan-600 dark:text-cyan-500') : 'bg-slate-100 dark:bg-slate-800 text-slate-400 dark:text-slate-600'}`}>
            <CheckCircle2 className="w-7 h-7" />
          </div>
        </div>
      </div>

      {/* ÁREA DE TRABAJO PRINCIPAL */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">

        {/* COLUMNA IZQUIERDA: INDEXACIÓN DE PILARES Y LECCIONES */}
        <div className="lg:col-span-4 space-y-4">
          <div className="p-4 bg-white dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800/80 rounded-2xl shadow-sm">
            <h3 className="text-sm font-bold text-slate-700 dark:text-slate-300 mb-3 px-1">
              {activeFramework === 'ISO' ? 'Secciones Anexo A' : 'Familias de Control NIST'}
            </h3>
            <div className="flex flex-wrap gap-2">
              {domains.map((dom) => (
                <button
                  key={dom.id}
                  onClick={() => handleDomainChange(dom.id)}
                  className={`px-3 py-1.5 text-xs font-bold rounded-xl border transition-all ${selectedDomain === dom.id
                    ? (activeFramework === 'ISO' 
                        ? 'bg-blue-50 dark:bg-blue-500/10 text-blue-600 dark:text-blue-400 border-blue-200 dark:border-blue-500/40' 
                        : 'bg-cyan-50 dark:bg-cyan-500/10 text-cyan-600 dark:text-cyan-400 border-cyan-200 dark:border-cyan-500/40')
                    : 'bg-slate-50 dark:bg-slate-900 hover:bg-slate-100 dark:hover:bg-slate-800/80 border-slate-200 dark:border-slate-800 text-slate-500 dark:text-slate-400'
                    }`}
                  title={dom.description}
                >
                  {dom.id}
                </button>
              ))}
            </div>
          </div>

          {/* LISTADO DE LECCIONES */}
          <div className="space-y-2">
            <h3 className="text-sm font-bold text-slate-700 dark:text-slate-300 px-1">Módulos de Control ({currentLessons.length})</h3>
            {currentLessons.length === 0 ? (
              <p className="text-xs italic text-slate-400 dark:text-slate-500 px-1">No hay lecciones registradas para este pilar.</p>
            ) : (
              currentLessons.map((lesson) => {
                const isCompleted = !!userProgress[lesson.id];
                const isActive = selectedLesson?.id === lesson.id;
                return (
                  <button
                    key={lesson.id}
                    onClick={() => handleLessonChange(lesson)}
                    className={`w-full p-4 rounded-2xl text-left border flex items-center justify-between transition-all group ${isActive
                      ? (activeFramework === 'ISO' ? 'bg-blue-600 border-blue-500' : 'bg-cyan-600 border-cyan-500') + ' text-white shadow-lg shadow-blue-600/10'
                      : 'bg-white dark:bg-slate-900/40 hover:bg-slate-50 dark:hover:bg-slate-900 border-slate-200 dark:border-slate-800/80'
                      }`}
                  >
                    <div className="space-y-1 pr-4">
                      <h4 className={`text-sm font-semibold tracking-tight leading-snug ${isActive ? 'text-white' : 'text-slate-800 dark:text-slate-200 group-hover:text-blue-500 dark:group-hover:text-blue-400'}`}>
                        {lesson.title}
                      </h4>
                      <div className="flex items-center space-x-2 text-[11px]">
                        <span className={isActive ? (activeFramework === 'ISO' ? 'text-blue-200' : 'text-cyan-200') : 'text-slate-400 dark:text-slate-500'}>{lesson.duration_minutes} min de lectura</span>
                        <span className={isActive ? 'text-white font-medium' : 'text-slate-500 dark:text-slate-400 font-medium'}>
                          {lesson.mapped_controls?.join(', ')}
                        </span>
                      </div>
                    </div>
                    {isCompleted ? (
                      <CheckCircle2 className={`w-5 h-5 flex-shrink-0 ${isActive ? 'text-white' : 'text-emerald-500'}`} />
                    ) : (
                      <ChevronRight className={`w-4 h-4 flex-shrink-0 opacity-40 group-hover:opacity-100 transition-opacity ${isActive ? 'text-white' : 'text-slate-400'}`} />
                    )}
                  </button>
                );
              })
            )}
          </div>
        </div>

        {/* COLUMNA DERECHA: TERMINAL DE LECTURA Y QUIZ */}
        <div className="lg:col-span-8 space-y-6">
          {selectedLesson ? (
            <>
              <div className="p-8 bg-white dark:bg-slate-900/30 border border-slate-200 dark:border-slate-800/80 rounded-3xl shadow-sm space-y-6">
                <div className="border-b border-slate-100 dark:border-slate-800 pb-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                  <div>
                    <span className={`text-[10px] font-bold tracking-widest ${activeFramework === 'ISO' ? 'text-blue-600 dark:text-blue-500' : 'text-cyan-600 dark:text-cyan-500'} uppercase`}>Marco de Referencia Oficial</span>
                    <h2 className="text-xl font-bold text-slate-800 dark:text-slate-100 mt-1">{selectedLesson.title}</h2>
                  </div>

                  <button
                    onClick={handleDownloadDocument}
                    disabled={downloading}
                    className={`shrink-0 px-3 py-2 ${activeFramework === 'ISO' ? 'bg-blue-50 dark:bg-blue-500/10 border-blue-200 dark:border-blue-500/30 text-blue-600 dark:text-blue-400 hover:bg-blue-100 dark:hover:bg-blue-500/20' : 'bg-cyan-50 dark:bg-cyan-500/10 border-cyan-200 dark:border-cyan-500/30 text-cyan-600 dark:text-cyan-400 hover:bg-cyan-100 dark:hover:bg-cyan-500/20'} font-mono font-bold rounded-xl text-xs flex items-center justify-center gap-2 transition-all shadow-sm ${downloading ? 'opacity-60 cursor-not-allowed' : ''}`}
                  >
                    <Download size={13} className={downloading ? "animate-bounce" : ""} />
                    <span>{downloading ? "ABRIENDO..." : "FRAMEWORK_DOC"}</span>
                  </button>
                </div>

                <div className="prose prose-slate dark:prose-invert max-w-none text-sm leading-relaxed text-slate-600 dark:text-slate-300 whitespace-pre-wrap">
                  {selectedLesson.content_markdown}
                </div>
              </div>

              {/* SECCIÓN DEL QUIZ */}
              {currentCheckpoint ? (
                <div className="p-6 border border-purple-200 dark:border-purple-500/20 bg-purple-50/30 dark:bg-purple-500/5 rounded-3xl space-y-5">
                  <div className="flex items-center space-x-2 text-purple-600 dark:text-purple-400">
                    <HelpCircle className="w-5 h-5" />
                    <h4 className="text-sm font-bold uppercase tracking-wider">⚡ Checkpoint de Validación</h4>
                  </div>

                  <p className="text-sm font-semibold text-slate-800 dark:text-slate-200 leading-snug">
                    {currentCheckpoint.question}
                  </p>

                  <div className="space-y-2">
                    {quizOptions.map((opt) => (
                      <button
                        key={opt.id}
                        onClick={() => { setSelectedAnswer(opt.id); setQuizFeedback(null); }}
                        className={`w-full p-4 rounded-xl text-left border text-xs font-medium transition-all flex items-start space-x-3 ${selectedAnswer === opt.id
                          ? 'bg-purple-100/60 dark:bg-purple-500/10 border-purple-400 dark:border-purple-500 text-purple-700 dark:text-purple-300'
                          : 'bg-white dark:bg-slate-900/50 hover:bg-slate-50 dark:hover:bg-slate-900 border-slate-200 dark:border-slate-800/60 text-slate-600 dark:text-slate-400'
                          }`}
                      >
                        <span className={`px-1.5 py-0.5 rounded-md text-[10px] font-bold ${selectedAnswer === opt.id ? 'bg-purple-600 text-white' : 'bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400'}`}>
                          {opt.id}
                        </span>
                        <span className="leading-normal text-slate-700 dark:text-slate-300">{opt.text}</span>
                      </button>
                    ))}
                  </div>

                  {quizFeedback && (
                    <div className={`p-4 rounded-xl border text-xs font-semibold ${quizFeedback.success
                      ? 'bg-emerald-50 dark:bg-emerald-500/10 border-emerald-200 dark:border-emerald-500/30 text-emerald-700 dark:text-emerald-400'
                      : 'bg-red-50 dark:bg-red-500/10 border-red-200 dark:border-red-500/30 text-red-700 dark:text-red-400'
                      }`}>
                      {quizFeedback.message}
                    </div>
                  )}

                  <div className="flex justify-end pt-2">
                    <button
                      onClick={handleVerifyAnswer}
                      disabled={!selectedAnswer}
                      className="px-5 py-2.5 bg-purple-600 hover:bg-purple-500 disabled:opacity-40 disabled:hover:bg-purple-600 text-white font-bold rounded-xl text-xs tracking-wide transition-all shadow-md shadow-purple-600/10"
                    >
                      Verificar Respuestas
                    </button>
                  </div>
                </div>
              ) : (
                <div className="p-6 border border-dashed border-slate-300 dark:border-slate-800 rounded-3xl text-center">
                  <p className="text-xs text-slate-400 dark:text-slate-500 italic">No se ha cargado una evaluación para este módulo específico.</p>
                </div>
              )}
            </>
          ) : (
            <div className="h-[40vh] flex items-center justify-center border border-dashed border-slate-300 dark:border-slate-800 rounded-3xl">
              <p className="text-slate-400 dark:text-slate-500 text-xs italic">Selecciona una lección para iniciar tu proceso de capacitación...</p>
            </div>
          )}
        </div>

      </div>
    </div>
  );
}