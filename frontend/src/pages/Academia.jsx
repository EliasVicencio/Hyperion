import React, { useState, useEffect } from 'react';
import { supabase } from '../supabaseClient'; // Ajusta la ruta según tu estructura de carpetas
import { motion, AnimatePresence } from 'framer-motion';

export default function Academia() {
  const [families, setFamilies] = useState([]);
  const [selectedLesson, setSelectedLesson] = useState(null);
  const [checkpoint, setCheckpoint] = useState(null);
  const [selectedAnswer, setSelectedAnswer] = useState('');
  const [metrics, setMetrics] = useState({ completed: 0, total: 0, percent: 0, hours: 0 });
  const [userId, setUserId] = useState(null);
  const [loading, setLoading] = useState(true);

  // 1. Cargar Usuario, Datos de la Academia y Métricas Iniciales
  useEffect(() => {
    async function initAcademy() {
      try {
        setLoading(true);
        
        // Obtener el usuario autenticado en Supabase
        const { data: { user } } = await supabase.auth.getUser();
        if (user) setUserId(user.id);

        // Cargar familias de controles y sus lecciones asociadas
        const { data: familyData, error: familyError } = await supabase
          .from('nist_families')
          .select(`
            id, name, description,
            academy_lessons (*)
          `)
          .order('sort_order', { foreignTable: 'academy_lessons', ascending: true });

        if (familyError) throw familyError;
        setFamilies(familyData || []);

        // Auto-seleccionar la primera lección si está disponible
        if (familyData?.[0]?.academy_lessons?.[0]) {
          await handleSelectLesson(familyData[0].academy_lessons[0], user?.id);
        }

        // Cargar métricas globales de progreso del alumno
        if (user) {
          await loadMetrics(user.id);
        }
      } catch (err) {
        console.error("Error inicializando el Compliance Hub:", err.message);
      } finally {
        setLoading(false);
      }
    }
    initAcademy();
  }, []);

  // 2. Función independiente para recargar las métricas de progreso
  const loadMetrics = async (uid) => {
    if (!uid) return;
    const { data, error } = await supabase.rpc('get_user_academy_metrics', { target_user_id: uid });
    if (!error && data && data.length > 0) {
      setMetrics({
        completed: data[0].lessons_completed,
        total: data[0].total_lessons,
        percent: parseFloat(data[0].percentage_completed) || 0,
        hours: parseFloat(data[0].hours_dedicated) || 0
      });
    }
  };

  // 3. Manejador para cambiar de lección activa y jalar su Checkpoint (Quiz)
  const handleSelectLesson = async (lesson, uid = userId) => {
    setSelectedLesson(lesson);
    setSelectedAnswer(''); // Resetear radio button
    setCheckpoint(null);

    // Intentar buscar el checkpoint/quiz asociado a esta lección
    const { data, error } = await supabase
      .from('academy_checkpoints')
      .select('*')
      .eq('lesson_id', lesson.id)
      .maybeSingle(); // Evita reventar si una lección no tiene quiz cargado aún

    if (!error && data) {
      setCheckpoint(data);
    }
  };

  // 4. Verificar respuesta y registrar completado en `user_academy_progress`
  const handleVerifyAnswer = async () => {
    if (!selectedAnswer || !checkpoint || !userId) return;

    const isCorrect = selectedAnswer === checkpoint.correct_option_id;

    if (isCorrect) {
      alert("¡Verificación Exitosa! Cumple rigurosamente con las directrices NIST SP 800-53.");
      
      // Guardar registro de completado de forma persistente
      const { error } = await supabase
        .from('user_academy_progress')
        .upsert({
          user_id: userId,
          lesson_id: selectedLesson.id,
          is_completed: true,
          selected_answer: selectedAnswer,
          completed_at: new Date().toISOString()
        }, { onConflict: 'user_id,lesson_id' });

      if (!error) {
        // Refrescar las métricas superiores en tiempo real al completar la lección
        await loadMetrics(userId);
      } else {
        console.error("Error guardando el progreso:", error.message);
      }
    } else {
      alert("Fallo de Validación: La respuesta seleccionada incumple los requerimientos técnicos del control federado.");
    }
  };

  if (loading) {
    return (
      <div className="h-[60vh] flex items-center justify-center">
        <p className="text-slate-400 italic animate-pulse">Cargando base de conocimientos NIST SP 800-53...</p>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      {/* --- ENCABEZADO Y TÍTULO DE TU CAPTURA --- */}
      <div>
        <div className="flex items-center gap-3 mb-2">
          <div className="p-2.5 bg-blue-600/20 text-blue-400 border border-blue-500/30 rounded-xl">
            {/* Icono de Libro/Academia */}
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.753 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253" />
            </svg>
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-100">Compliance Hub & Academia NIST</h1>
        </div>
        <p className="text-sm text-slate-400 pl-1">
          Centro de capacitación técnica y legal de la organización bajo directivas del estándar <span className="text-slate-200 font-semibold">NIST SP 800-53 Rev. 5</span>
        </p>
      </div>

      {/* --- TARJETAS DE MÉTRICAS DINÁMICAS --- */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        {/* Card 1: Porcentaje */}
        <div className="p-5 bg-slate-900/40 border border-slate-850 rounded-2xl relative overflow-hidden">
          <p className="text-xs font-mono uppercase text-slate-500 tracking-wider">Certificación Global</p>
          <p className="text-2xl font-bold mt-1 text-slate-200 font-mono">{metrics.percent}% <span className="text-sm font-normal text-slate-400">COMPLETADO</span></p>
          {/* Barra de progreso visual de tu captura */}
          <div className="w-full h-1.5 bg-slate-800 rounded-full mt-4 overflow-hidden">
            <motion.div 
              className="h-full bg-blue-500"
              initial={{ width: 0 }}
              animate={{ width: `${metrics.percent}%` }}
              transition={{ duration: 0.5 }}
            />
          </div>
        </div>

        {/* Card 2: Horas */}
        <div className="p-5 bg-slate-900/40 border border-slate-850 rounded-2xl">
          <p className="text-xs font-mono uppercase text-slate-500 tracking-wider">Tiempo Dedicado</p>
          <p className="text-2xl font-bold mt-1 text-slate-200 font-mono">
            {metrics.hours} <span className="text-sm font-normal text-slate-400">/ 15 HORAS</span>
          </p>
          <p className="text-xs text-slate-500 mt-3">Calculado dinámicamente según duración de laboratorios superados.</p>
        </div>

        {/* Card 3: Controles Entendidos */}
        <div className="p-5 bg-slate-900/40 border border-slate-850 rounded-2xl flex items-center justify-between">
          <div>
            <p className="text-xs font-mono uppercase text-slate-500 tracking-wider">Controles Entendidos</p>
            <p className="text-2xl font-bold mt-1 text-slate-200 font-mono">
              {metrics.completed} <span className="text-sm font-normal text-slate-400">CONTROLES VALIDADOS</span>
            </p>
          </div>
          <div className="p-3 bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 rounded-full">
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" d="M5 13l4 4L19 7" />
            </svg>
          </div>
        </div>
      </div>

      {/* --- SECCIÓN PRINCIPAL EN DOS COLUMNAS --- */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-start">
        
        {/* COLUMNA IZQUIERDA (2/3): Listado de Familias y Temarios */}
        <div className="lg:col-span-2 space-y-6">
          {families.map(family => (
            <div key={family.id} className="p-6 bg-slate-900/30 border border-slate-850 rounded-2xl space-y-4">
              <div className="flex items-center gap-2">
                <span className="text-[10px] font-mono px-2 py-0.5 bg-blue-500/10 text-blue-400 border border-blue-500/20 rounded uppercase tracking-widest font-semibold">
                  NIST SP 800-53 ({family.id})
                </span>
              </div>
              <div>
                <h3 className="text-lg font-bold text-slate-200">Familia {family.id}: {family.name}</h3>
                <p className="text-xs text-slate-400 mt-1">{family.description}</p>
              </div>

              {/* Botones/Lecciones de esta familia */}
              <div className="space-y-2.5 pt-2">
                {family.academy_lessons?.map(lesson => {
                  const isSelected = selectedLesson?.id === lesson.id;
                  return (
                    <button
                      key={lesson.id}
                      onClick={() => handleSelectLesson(lesson)}
                      className={`w-full text-left p-3.5 rounded-xl border text-xs transition-all flex justify-between items-center ${
                        isSelected 
                          ? 'bg-blue-600/10 border-blue-500 text-blue-400 shadow-md' 
                          : 'bg-slate-950/40 border-slate-850 text-slate-350 hover:bg-slate-900/40'
                      }`}
                    >
                      <span className="font-medium tracking-wide">{lesson.title}</span>
                      <span className="text-[10px] font-mono text-slate-500 bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
                        {lesson.duration_minutes} min
                      </span>
                    </button>
                  );
                })}
              </div>
            </div>
          ))}
        </div>

        {/* COLUMNA DERECHA (1/3): Terminal de Estudio y Checkpoint Dinámico */}
        <div className="lg:col-span-1">
          <AnimatePresence mode="wait">
            {selectedLesson ? (
              <motion.div
                key={selectedLesson.id}
                initial={{ opacity: 0, x: 15 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -15 }}
                transition={{ duration: 0.2 }}
                className="p-5 bg-slate-900/50 border border-slate-800 rounded-2xl space-y-5"
              >
                {/* Cabecera Terminal */}
                <div className="flex justify-between items-center pb-3 border-b border-slate-850">
                  <h4 className="text-[10px] font-mono uppercase text-slate-400 tracking-widest flex items-center gap-1.5">
                    <span className="w-1.5 h-1.5 bg-blue-500 rounded-full animate-pulse" />
                    TERMINAL DE ESTUDIO
                  </h4>
                  <span className="text-[9px] font-mono text-slate-500 uppercase tracking-tight">LECTURE_MODE</span>
                </div>

                {/* Contenido Formateado */}
                <div className="text-xs text-slate-300 font-sans leading-relaxed whitespace-pre-wrap">
                  {selectedLesson.content_markdown}
                </div>

                {/* Mapeo de controles pequeños en el pie de la terminal */}
                {selectedLesson.mapped_controls && (
                  <div className="flex gap-1.5 pt-2">
                    <span className="text-[9px] font-mono text-slate-500 mt-0.5">MARCO REGLAMENTARIO ASOCIADO:</span>
                    {selectedLesson.mapped_controls.map(ctrl => (
                      <span key={ctrl} className="text-[9px] font-mono text-slate-400 bg-slate-950 px-1.5 py-0.5 rounded border border-slate-850">
                        {ctrl}
                      </span>
                    ))}
                  </div>
                )}

                {/* CHECKPOINT INTERACTIVO (QUIZ) */}
                {checkpoint && (
                  <div className="mt-6 pt-5 border-t border-slate-850 space-y-4">
                    <h5 className="text-[10px] font-mono text-purple-400 tracking-widest font-semibold">
                      ⚡ CHECKPOINT DE VALIDACIÓN (NIST)
                    </h5>
                    <p className="text-xs font-medium text-slate-200 leading-normal">
                      {checkpoint.question}
                    </p>
                    
                    {/* Opciones de respuesta */}
                    <div className="space-y-2">
                      {checkpoint.options?.map(opt => {
                        const isChecked = selectedAnswer === opt.id;
                        return (
                          <label 
                            key={opt.id} 
                            className={`flex items-start gap-3 p-3 rounded-xl border text-[11px] cursor-pointer transition-all ${
                              isChecked 
                                ? 'bg-purple-600/10 border-purple-500/80 text-purple-300' 
                                : 'bg-slate-950/60 border-slate-850 hover:bg-slate-900/60 text-slate-400'
                            }`}
                          >
                            <input 
                              type="radio" 
                              name="checkpoint-option" 
                              value={opt.id}
                              checked={isChecked}
                              onChange={(e) => setSelectedAnswer(e.target.value)}
                              className="mt-0.5 accent-purple-500 focus:ring-0"
                            />
                            <span className="leading-tight">{opt.id}) {opt.text}</span>
                          </label>
                        );
                      })}
                    </div>

                    {/* Botón de Enviar */}
                    <button
                      onClick={handleVerifyAnswer}
                      disabled={!selectedAnswer}
                      className={`w-full py-2.5 mt-2 font-mono font-bold text-[10px] tracking-wider rounded-xl transition-all shadow-lg ${
                        selectedAnswer
                          ? 'bg-purple-600 hover:bg-purple-500 text-white shadow-purple-900/20 cursor-pointer'
                          : 'bg-slate-800 text-slate-500 cursor-not-allowed shadow-none'
                      }`}
                    >
                      🚀 ENVIAR_RESPUESTA_Y_COMPLETAR
                    </button>
                  </div>
                )}
              </motion.div>
            ) : (
              <div className="p-5 bg-slate-900/20 border border-dashed border-slate-800 rounded-2xl text-center py-12">
                <p className="text-xs text-slate-500 italic">Selecciona un módulo del catálogo normativo para iniciar la terminal de estudio.</p>
              </div>
            )}
          </AnimatePresence>
        </div>

      </div>
    </div>
  );
}