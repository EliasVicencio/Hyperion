import React, { useState, useEffect } from 'react';
import { supabase } from '../supabaseClient'; // Ajusta la ruta según la estructura de tu proyecto
import { BookOpen, Clock, CheckCircle2, AlertTriangle, HelpCircle, ChevronRight } from 'lucide-react';

export default function Academia({ user }) {
  // Estados de carga e interfaz
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Estados de datos provenientes de la BD
  const [families, setFamilies] = useState([]);
  const [lessons, setLessons] = useState([]);
  const [checkpoints, setCheckpoints] = useState([]);

  // Estados de navegación e interacción del usuario
  const [selectedFamily, setSelectedFamily] = useState(null);
  const [selectedLesson, setSelectedLesson] = useState(null);
  const [selectedAnswer, setSelectedAnswer] = useState(null);
  const [quizFeedback, setQuizFeedback] = useState(null); // { success: boolean, message: string }

  // Estado de progreso local del usuario (Salvaguardado contra fallas de JSON)
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

  // 1. CARGA INICIAL DE DATOS DESDE SUPABASE
  useEffect(() => {
    async function fetchAcademyData() {
      try {
        setLoading(true);
        setError(null);

        // Traer de forma paralela familias, lecciones y checkpoints
        const [resFamilies, resLessons, resCheckpoints] = await Promise.all([
          supabase.from('nist_families').select('*').order('id', { ascending: true }),
          supabase.from('academy_lessons').select('*').order('sort_order', { ascending: true }),
          supabase.from('academy_checkpoints').select('*')
        ]);

        if (resFamilies.error) throw resFamilies.error;
        if (resLessons.error) throw resLessons.error;
        if (resCheckpoints.error) throw resCheckpoints.error;

        setFamilies(resFamilies.data || []);
        setLessons(resLessons.data || []);
        setCheckpoints(resCheckpoints.data || []);

        // Preseleccionar la primera familia y lección si existen
        if (resFamilies.data && resFamilies.data.length > 0) {
          const firstFam = resFamilies.data[0].id;
          setSelectedFamily(firstFam);
          
          const firstLess = resLessons.data.find(l => l.family_id === firstFam);
          if (firstLess) setSelectedLesson(firstLess);
        }

      } catch (err) {
        print("Error inicializando el Compliance Hub:", err.message);
        setError(err.message);
      } finally {
        // 🛡️ SEGURO: Garantiza que el loader se apague pase lo que pase
        setLoading(false);
      }
    }

    fetchAcademyData();
  }, []);

  // Guardar progreso en LocalStorage cada vez que cambie
  useEffect(() => {
    localStorage.setItem('hyperion_academy_progress', JSON.stringify(userProgress));
  }, [userProgress]);

  // 2. FILTRADO DE LECCIONES SEGÚN LA FAMILIA SELECCIONADA
  // Normalizamos strings para evitar fallas por mayúsculas/minúsculas
  const currentLessons = lessons.filter(
    lesson => lesson.family_id?.toUpperCase() === selectedFamily?.toUpperCase()
  );

  // Buscar el checkpoint (quiz) correspondiente a la lección activa
  const currentCheckpoint = checkpoints.find(
    cp => cp.lesson_id === selectedLesson?.id
  );

  // 3. PROCESAMIENTO SEGURO DE LAS OPCIONES DEL QUIZ (Evita el crash de undefined JSON)
  const renderOptions = () => {
    if (!currentCheckpoint) return [];
    
    // Si Supabase ya lo parseó como objeto/array (jsonb nativo), lo usamos directo.
    if (Array.isArray(currentCheckpoint.options)) {
      return currentCheckpoint.options;
    }
    
    // Fallback por si viene codificado como string puro
    if (typeof currentCheckpoint.options === 'string') {
      try {
        return JSON.parse(currentCheckpoint.options);
      } catch (e) {
        console.error("Error parseando opciones en formato string:", e);
        return [];
      }
    }
    return [];
  };

  const quizOptions = renderOptions();

  // 4. MANEJADORES DE ACCIONES
  const handleFamilyChange = (familyId) => {
    setSelectedFamily(familyId);
    setQuizFeedback(null);
    setSelectedAnswer(null);
    
    const firstLessonOfFamily = lessons.find(l => l.family_id?.toUpperCase() === familyId.toUpperCase());
    setSelectedLesson(firstLessonOfFamily || null);
  };

  const handleLessonChange = (lesson) => {
    setSelectedLesson(lesson);
    setQuizFeedback(null);
    setSelectedAnswer(null);
  };

  const handleVerifyAnswer = () => {
    if (!selectedAnswer || !currentCheckpoint) return;

    if (selectedAnswer === currentCheckpoint.correct_option_id) {
      setQuizFeedback({
        success: true,
        message: "¡Excelente! Respuesta correcta. El control ha sido validado en tu perfil operativo."
      });
      // Marcar lección como completada
      setUserProgress(prev => ({
        ...prev,
        [selectedLesson.id]: true
      }));
    } else {
      setQuizFeedback({
        success: false,
        message: "Respuesta incorrecta. Repasa las directrices del control NIST e inténtalo de nuevo."
      });
    }
  };

  // 5. CÁLCULO DE MÉTRICAS OPERATIVAS
  const totalLessonsCount = lessons.length || 1;
  const completedCount = Object.keys(userProgress).filter(id => userProgress[id]).length;
  const globalCompletionPercentage = Math.round((completedCount / totalLessonsCount) * 100);
  const totalHoursDedicated = (completedCount * 15) / 60; // Asumiendo ~15 minutos por bloque técnico

  if (loading) {
    return (
      <div className="h-[70vh] flex flex-col items-center justify-center space-y-4">
        <div className="w-12 h-12 border-4 border-blue-500 border-t-transparent rounded-full animate-spin"></div>
        <p className="text-slate-400 font-medium animate-pulse">Sincronizando Base de Conocimientos NIST...</p>
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
    <div className="space-y-8">
      {/* CABECERA Y TITULARES */}
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center space-x-3 mb-2">
            <div className="p-2.5 bg-blue-500/10 text-blue-500 rounded-2xl border border-blue-500/20">
              <BookOpen className="w-6 h-6" />
            </div>
            <h1 className="text-2xl font-bold tracking-tight">Compliance Hub & Academia NIST</h1>
          </div>
          <p className="text-slate-400 text-sm">
            Centro de capacitación técnica y legal de la organización bajo directivas del estándar <span className="text-blue-400 font-semibold">NIST SP 800-53 Rev. 5</span>.
          </p>
        </div>
      </div>

      {/* DASHBOARD DE ESTADÍSTICAS */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        <div className="p-6 dark:bg-slate-900/40 bg-white border dark:border-slate-800/80 border-slate-200 rounded-2xl relative overflow-hidden">
          <p className="text-xs font-semibold uppercase tracking-wider text-slate-500 mb-1">Certificación Global</p>
          <p className="text-3xl font-bold text-slate-100">{globalCompletionPercentage}%</p>
          <div className="w-full bg-slate-800 h-2 rounded-full mt-4 overflow-hidden">
            <div className="bg-blue-500 h-full transition-all duration-500" style={{ width: `${globalCompletionPercentage}%` }}></div>
          </div>
        </div>

        <div className="p-6 dark:bg-slate-900/40 bg-white border dark:border-slate-800/80 border-slate-200 rounded-2xl">
          <p className="text-xs font-semibold uppercase tracking-wider text-slate-500 mb-1">Tiempo Dedicado</p>
          <p className="text-3xl font-bold text-slate-100">{totalHoursDedicated.toFixed(1)} <span className="text-sm text-slate-500 font-normal">/ 15 HORAS</span></p>
          <p className="text-xs text-slate-400 mt-3 flex items-center gap-1"><Clock className="w-3.5 h-3.5" /> Calculado dinámicamente por módulos superados.</p>
        </div>

        <div className="p-6 dark:bg-slate-900/40 bg-white border dark:border-slate-800/80 border-slate-200 rounded-2xl flex items-center justify-between">
          <div>
            <p className="text-xs font-semibold uppercase tracking-wider text-slate-500 mb-1">Controles Entendidos</p>
            <p className="text-3xl font-bold text-slate-100">{completedCount} <span className="text-sm text-slate-500 font-normal">CONTROLES</span></p>
          </div>
          <div className={`p-3.5 rounded-2xl ${completedCount > 0 ? 'bg-emerald-500/10 text-emerald-500' : 'bg-slate-800 text-slate-600'}`}>
            <CheckCircle2 className="w-7 h-7" />
          </div>
        </div>
      </div>

      {/* ÁREA DE TRABAJO PRINCIPAL */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
        
        {/* COLUMNA IZQUIERDA: INDEXACIÓN DE FAMILIAS Y LECCIONES */}
        <div className="lg:col-span-4 space-y-4">
          <div className="p-4 dark:bg-slate-900/60 bg-white border dark:border-slate-800/80 border-slate-200 rounded-2xl">
            <h3 className="text-sm font-bold text-slate-300 mb-3 px-1">Familias de Control</h3>
            <div className="flex flex-wrap gap-2">
              {families.map((fam) => (
                <button
                  key={fam.id}
                  onClick={() => handleFamilyChange(fam.id)}
                  className={`px-3 py-1.5 text-xs font-bold rounded-xl border transition-all ${
                    selectedFamily === fam.id
                      ? 'bg-blue-500/10 dark:text-blue-400 text-blue-600 border-blue-500/40'
                      : 'dark:bg-slate-900 dark:hover:bg-slate-800/80 bg-slate-50 border-slate-200 dark:border-slate-800 text-slate-400'
                  }`}
                  title={fam.description}
                >
                  {fam.id}
                </button>
              ))}
            </div>
          </div>

          {/* LISTADO DE LECCIONES */}
          <div className="space-y-2">
            <h3 className="text-sm font-bold text-slate-300 px-1">Módulos Disponibles ({currentLessons.length})</h3>
            {currentLessons.length === 0 ? (
              <p className="text-xs italic text-slate-500 px-1">No hay lecciones registradas para esta familia.</p>
            ) : (
              currentLessons.map((lesson) => {
                const isCompleted = !!userProgress[lesson.id];
                const isActive = selectedLesson?.id === lesson.id;
                return (
                  <button
                    key={lesson.id}
                    onClick={() => handleLessonChange(lesson)}
                    className={`w-full p-4 rounded-2xl text-left border flex items-center justify-between transition-all group ${
                      isActive
                        ? 'bg-blue-600 border-blue-500 text-white shadow-lg shadow-blue-600/10'
                        : 'dark:bg-slate-900/40 dark:hover:bg-slate-900 bg-white hover:bg-slate-50 dark:border-slate-800/80 border-slate-200'
                    }`}
                  >
                    <div className="space-y-1 pr-4">
                      <h4 className={`text-sm font-semibold tracking-tight leading-snug ${isActive ? 'text-white' : 'dark:text-slate-200 text-slate-700 group-hover:text-blue-400'}`}>
                        {lesson.title}
                      </h4>
                      <div className="flex items-center space-x-2 text-[11px]">
                        <span className={isActive ? 'text-blue-200' : 'text-slate-500'}>{lesson.duration_minutes} min de lectura</span>
                        <span className={isActive ? 'text-blue-300' : 'text-slate-400 font-medium'}>
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
              {/* PANEL DE CONTENIDO MARKDOWN */}
              <div className="p-8 dark:bg-slate-900/30 bg-white border dark:border-slate-800/80 border-slate-200 rounded-3xl shadow-sm space-y-6">
                <div className="border-b dark:border-slate-800 border-slate-100 pb-4">
                  <span className="text-[10px] font-bold tracking-widest text-blue-500 uppercase">Documentación Técnica</span>
                  <h2 className="text-xl font-bold dark:text-slate-100 text-slate-800 mt-1">{selectedLesson.title}</h2>
                </div>

                {/* VISOR TEXTUAL */}
                <div className="prose prose-slate dark:prose-invert max-w-none text-sm leading-relaxed dark:text-slate-300 text-slate-600 whitespace-pre-wrap">
                  {selectedLesson.content_markdown}
                </div>
              </div>

              {/* SECCIÓN DEL CHECKPOINT (QUIZ) */}
              {currentCheckpoint ? (
                <div className="p-6 border border-purple-500/20 bg-purple-500/5 rounded-3xl space-y-5">
                  <div className="flex items-center space-x-2 text-purple-400">
                    <HelpCircle className="w-5 h-5" />
                    <h4 className="text-sm font-bold uppercase tracking-wider">⚡ Checkpoint de Validación</h4>
                  </div>
                  
                  <p className="text-sm font-semibold dark:text-slate-200 text-slate-700 leading-snug">
                    {currentCheckpoint.question}
                  </p>

                  <div className="space-y-2">
                    {quizOptions.map((opt) => (
                      <button
                        key={opt.id}
                        onClick={() => { setSelectedAnswer(opt.id); setQuizFeedback(null); }}
                        className={`w-full p-4 rounded-xl text-left border text-xs font-medium transition-all flex items-start space-x-3 ${
                          selectedAnswer === opt.id
                            ? 'bg-purple-500/10 border-purple-500 text-purple-300'
                            : 'dark:bg-slate-900/50 dark:hover:bg-slate-900 bg-white border-slate-200 dark:border-slate-800/60 text-slate-400 hover:text-slate-300'
                        }`}
                      >
                        <span className={`px-1.5 py-0.5 rounded-md text-[10px] font-bold ${selectedAnswer === opt.id ? 'bg-purple-500 text-white' : 'dark:bg-slate-800 bg-slate-100 text-slate-400'}`}>
                          {opt.id}
                        </span>
                        <span className="leading-normal dark:text-slate-300 text-slate-600">{opt.text}</span>
                      </button>
                    ))}
                  </div>

                  {/* FEEDBACK DEL RESULTADO */}
                  {quizFeedback && (
                    <div className={`p-4 rounded-xl border text-xs font-semibold ${
                      quizFeedback.success 
                        ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400' 
                        : 'bg-red-500/10 border-red-500/30 text-red-400'
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
                <div className="p-6 border border-dashed dark:border-slate-800 border-slate-300 rounded-3xl text-center">
                  <p className="text-xs text-slate-500 italic">No se ha cargado una evaluación para este módulo específico.</p>
                </div>
              )}
            </>
          ) : (
            <div className="h-[40vh] flex items-center justify-center border border-dashed dark:border-slate-800 border-slate-300 rounded-3xl">
              <p className="dark:text-slate-500 text-slate-400 text-xs italic">Selecciona una lección para iniciar tu proceso de capacitación...</p>
            </div>
          )}
        </div>

      </div>
    </div>
  );
}