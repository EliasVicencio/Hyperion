import React, { useState, useEffect } from 'react';
import { BookOpen, Award, Clock, CheckCircle2, ChevronRight, Play, FileText, HelpCircle, Shield, AlertCircle } from 'lucide-react';

export default function Academia() {
  const [modulos, setModulos] = useState([]);
  const [moduloActivo, setModuloActivo] = useState(null);
  const [leccionActiva, setLeccionActiva] = useState(null);
  const [stats, setStats] = useState({ global: 0, horas: 0, controles: 0 });
  
  const [loading, setLoading] = useState(true);
  const [testCompletado, setTestCompletado] = useState(false);
  const [respuestaSeleccionada, setRespuestaSeleccionada] = useState(null);

  // 🔌 Obtener datos asíncronos desde FastAPI
  const fetchPlanEstudio = async () => {
    try {
      const response = await fetch('/api/v1/academia/modulos');
      if (!response.ok) throw new Error("Error obteniendo el esquema reglamentario.");
      const data = await response.json();
      
      setModulos(data.modulos || []);
      setStats({
        global: data.certificacion_global || 0,
        horas: data.horas_dedicadas || 0,
        controles: data.controles_validados || 0
      });

      // Selección por defecto inicial
      if (data.modulos && data.modulos.length > 0) {
        setModuloActivo(data.modulos[0]);
        if (data.modulos[0].lecciones && data.modulos[0].lecciones.length > 0) {
          setLeccionActiva(data.modulos[0].lecciones[0]);
        }
      }
      setLoading(false);
    } catch (error) {
      console.error("🚨 Fallo de sincronización con Academia API:", error);
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchPlanEstudio();
  }, []);

  const seleccionarLeccion = (modulo, leccion) => {
    setModuloActivo(modulo);
    setLeccionActiva(leccion);
    setTestCompletado(false);
    setRespuestaSeleccionada(null);
  };

  // 🔌 Persistir progreso en la Base de Datos mediante API POST
  const marcarLeccionCompletada = async () => {
    if (respuestaSeleccionada !== 'B') return;

    try {
      const response = await fetch('/api/v1/academia/completar-leccion', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          modulo_id: moduloActivo.id,
          leccion_id: leccionActiva.id,
          correcta: true
        })
      });

      if (!response.ok) throw new Error("La base de datos rechazó la firma de progreso.");
      
      setTestCompletado(true);
      // Refrescamos estados para recalcular barras de progreso globales
      fetchPlanEstudio();
    } catch (error) {
      console.error("🚨 Error persistiendo progreso:", error);
      alert("No se pudo certificar la lección en los nodos de control de Hyperion.");
    }
  };

  if (loading) {
    return <div className="p-8 font-mono text-xs text-slate-500 tracking-widest animate-pulse">SINKING_WITH_NIST_CORE_API...</div>;
  }

  if (!moduloActivo || !leccionActiva) {
    return <div className="p-8 font-mono text-xs text-red-400">ERROR_NO_DATABASES_LOADED</div>;
  }

  return (
    <div className="space-y-6 text-slate-300">
      
      {/* Encabezado Principal */}
      <header>
        <h1 className="text-3xl font-bold text-white tracking-tight flex items-center gap-3">
          <div className="flex items-center justify-center w-10 h-10 rounded-xl bg-gradient-to-br from-indigo-600 to-violet-600 text-white shadow-[0_0_15px_rgba(99,102,241,0.3)]">
            <BookOpen size={22} />
          </div>
          Compliance Hub & Academia NIST
        </h1>
        <p className="text-slate-400 text-sm mt-1">
          Centro de capacitación técnica y legal de la organización bajo directivas del estándar <b>NIST SP 800-53 Rev. 5</b>
        </p>
      </header>

      {/* PANEL SUPERIOR: ESTADÍSTICAS DEL ESTUDIANTE */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="p-4 rounded-2xl border border-slate-800/80 bg-slate-900/40 backdrop-blur-sm flex items-center gap-4">
          <div className="p-3 rounded-xl bg-indigo-500/10 text-indigo-400">
            <Award size={24} />
          </div>
          <div>
            <span className="text-[10px] uppercase font-bold tracking-wider text-slate-500 block">Certificación Global</span>
            <span className="text-sm font-mono font-bold text-slate-200">{stats.global}% COMPLETADO</span>
          </div>
        </div>

        <div className="p-4 rounded-2xl border border-slate-800/80 bg-slate-900/40 backdrop-blur-sm flex items-center gap-4">
          <div className="p-3 rounded-xl bg-violet-500/10 text-violet-400">
            <Clock size={24} />
          </div>
          <div>
            <span className="text-[10px] uppercase font-bold tracking-wider text-slate-500 block">Tiempo Dedicado</span>
            <span className="text-sm font-mono font-bold text-slate-200">{stats.horas} / 15 HORAS</span>
          </div>
        </div>

        <div className="p-4 rounded-2xl border border-slate-800/80 bg-slate-900/40 backdrop-blur-sm flex items-center gap-4">
          <div className="p-3 rounded-xl bg-emerald-500/10 text-emerald-400">
            <CheckCircle2 size={24} />
          </div>
          <div>
            <span className="text-[10px] uppercase font-bold tracking-wider text-slate-500 block">Controles Entendidos</span>
            <span className="text-sm font-mono font-bold text-slate-200">{stats.controles} CONTROLES VALIDADOS</span>
          </div>
        </div>
      </div>

      {/* CUERPO CENTRAL DE LA ACADEMIA */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* COLUMNA IZQUIERDA: LISTADO DE MÓDULOS Y LECCIONES */}
        <div className="lg:col-span-2 space-y-4">
          {modulos.map(modulo => (
            <div key={modulo.id} className="bg-slate-900/40 border border-slate-800/80 rounded-2xl p-5 backdrop-blur-sm space-y-3">
              <div className="flex justify-between items-start gap-4">
                <div>
                  <span className="text-[10px] font-mono bg-indigo-950/60 text-indigo-400 border border-indigo-900/50 px-2 py-0.5 rounded font-bold">
                    {modulo.norma}
                  </span>
                  <h3 className="text-base font-bold text-white mt-1.5">{modulo.titulo}</h3>
                </div>
                <div className="text-right font-mono text-xs shrink-0">
                  <span className="text-slate-400 font-bold">{modulo.progreso}%</span>
                  <div className="w-24 bg-slate-950 h-1.5 rounded-full mt-1 overflow-hidden border border-slate-900">
                    <div className="bg-gradient-to-r from-indigo-500 to-violet-500 h-full transition-all duration-300" style={{ width: `${modulo.progreso}%` }} />
                  </div>
                </div>
              </div>

              <p className="text-xs text-slate-400 leading-relaxed">{modulo.descripcion}</p>

              {/* Lista de Lecciones de este módulo */}
              <div className="pt-2 space-y-2">
                {modulo.lecciones && modulo.lecciones.map(leccion => {
                  const esActiva = leccionActiva.id === leccion.id;
                  return (
                    <div
                      key={leccion.id}
                      onClick={() => seleccionarLeccion(modulo, leccion)}
                      className={`w-full text-left p-3 rounded-xl border flex items-center justify-between transition-all cursor-pointer font-mono text-xs ${
                        esActiva 
                          ? 'bg-indigo-500/10 border-indigo-500/40 shadow-md' 
                          : 'bg-slate-950/40 border-slate-900/60 hover:border-slate-800'
                      }`}
                    >
                      <div className="flex items-center gap-3">
                        <span className={`w-2 h-2 rounded-full ${leccion.completada ? 'bg-emerald-400' : 'bg-slate-700'}`} />
                        <span className={esActiva ? 'text-white font-bold' : 'text-slate-300'}>{leccion.titulo}</span>
                      </div>
                      <div className="flex items-center gap-2 text-slate-500 text-[11px]">
                        <span>{leccion.duracion}</span>
                        <ChevronRight size={14} className={esActiva ? "text-indigo-400 translate-x-1 transition-all" : ""} />
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          ))}
        </div>

        {/* COLUMNA DERECHA: VISOR INMERSIVO DE LECCIÓN */}
        <div className="space-y-4">
          <div className="bg-slate-900/40 border border-slate-800/80 rounded-2xl p-5 shadow-xl backdrop-blur-sm space-y-4 flex flex-col justify-between min-h-[500px]">
            
            <div className="space-y-4">
              {/* Encabezado del visor */}
              <div className="flex items-center justify-between border-b border-slate-800/60 pb-3">
                <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider flex items-center gap-2">
                  <FileText size={14} className="text-indigo-400" /> Terminal de Estudio
                </h4>
                <span className="text-[10px] text-slate-500 font-mono font-bold">LECTURE_MODE</span>
              </div>

              {/* Título e Información de la Lección */}
              <div>
                <h2 className="text-lg font-bold text-white tracking-tight">{leccionActiva.titulo}</h2>
                <span className="text-[10px] font-mono text-slate-500 block mt-0.5 uppercase">Marco Reglamentativo Asociado: {moduloActivo.norma}</span>
              </div>

              {/* Bloque de Contenido Texto Tipo Terminal */}
              <div className="bg-slate-950/80 border border-slate-900 rounded-xl p-4 font-sans text-xs text-slate-300 leading-relaxed space-y-3 shadow-inner max-h-[260px] overflow-y-auto">
                <p>{leccionActiva.contenido}</p>
              </div>

              {/* MINI CUESTIONARIO DE COMPROBACIÓN INTEGRADA */}
              <div className="bg-slate-950/30 border border-slate-900/60 rounded-xl p-3.5 space-y-3">
                <span className="text-[10px] font-bold text-slate-400 flex items-center gap-1.5 uppercase font-mono">
                  <HelpCircle size={13} className="text-violet-400" /> Checkpoint de Validación (NIST)
                </span>
                <p className="text-[11px] font-mono text-slate-300 leading-normal">
                  ¿Qué sucede bajo el control NIST AU-9 si una fila de logs es editada directamente en Supabase sin recalcular la cadena?
                </p>
                
                {/* Opciones de respuesta simuladas */}
                <div className="space-y-2 font-mono text-[10px]">
                  <button 
                    disabled={testCompletado}
                    onClick={() => setRespuestaSeleccionada('A')}
                    className={`w-full text-left p-2 rounded-lg border transition-all ${
                      respuestaSeleccionada === 'A' ? 'bg-red-500/10 border-red-500/40 text-red-400' : 'bg-slate-950/40 border-slate-900 text-slate-400 hover:border-slate-800'
                    }`}
                  >
                    A) El sistema corrige el texto automáticamente sincronizando con caché fría.
                  </button>
                  <button 
                    disabled={testCompletado}
                    onClick={() => setRespuestaSeleccionada('B')}
                    className={`w-full text-left p-2 rounded-lg border transition-all ${
                      testCompletado ? 'bg-emerald-500/10 border-emerald-500/40 text-emerald-400 font-bold' : respuestaSeleccionada === 'B' ? 'bg-indigo-500/20 border-indigo-500 text-white' : 'bg-slate-950/40 border-slate-900 text-slate-400 hover:border-slate-800'
                    }`}
                  >
                    B) Se rompe la referencia secuencial del bloque SHA-256 revocando el estado de confianza.
                  </button>
                </div>
              </div>
            </div>

            {/* Acciones del visor (Botón Inferior) */}
            <div className="pt-4 border-t border-slate-800/40">
              {testCompletado ? (
                <div className="bg-emerald-500/10 border border-emerald-500/20 p-2.5 rounded-xl text-xs font-mono text-emerald-400 flex items-center justify-center gap-2">
                  <CheckCircle2 size={14} /> ¡Lección Validada y Registrada con Éxito!
                </div>
              ) : (
                <button
                  onClick={marcarLeccionCompletada}
                  disabled={respuestaSeleccionada !== 'B'}
                  className={`w-full py-2.5 rounded-xl text-xs font-semibold flex items-center justify-center gap-2 border font-mono transition-all shadow-md ${
                    respuestaSeleccionada === 'B'
                      ? 'bg-gradient-to-r from-indigo-600 to-violet-600 text-white border-indigo-500 shadow-[0_0_15px_rgba(99,102,241,0.2)] hover:opacity-90'
                      : 'bg-slate-950/50 text-slate-600 border-slate-900 cursor-not-allowed'
                  }`}
                >
                  <Play size={12} /> ENVIAR_RESPUESTA_Y_COMPLETAR
                </button>
              )}
            </div>

          </div>

          {/* Tarjeta Informativa de la Academia */}
          <div className="bg-[#040712] border border-slate-900/80 rounded-2xl p-4 space-y-2">
            <span className="text-[10px] font-bold text-slate-500 flex items-center gap-1.5 uppercase font-mono">
              🛡️ Auditoría de Aprendizaje Corporativo
            </span>
            <p className="text-[10px] font-mono text-slate-500 leading-relaxed">
              El avance de cada operador se almacena en Supabase. Completar las familias de controles de este Hub desbloquea tokens de autorización extendida dentro de los nodos críticos de la plataforma.
            </p>
          </div>
        </div>

      </div>
    </div>
  );
}