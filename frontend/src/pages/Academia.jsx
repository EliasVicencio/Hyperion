import React, { useState, useEffect } from 'react';
import { 
  BookOpen, 
  CheckCircle2, 
  Download, 
  Clock, 
  Award, 
  ShieldAlert,
  ChevronRight, 
  PlayCircle, 
  FileText,
  Loader2,
  RefreshCw
} from 'lucide-react';

export default function Academia() {
  const [modulos, setModulos] = useState([]);
  const [loading, setLoading] = useState(true);
  const [downloading, setDownloading] = useState(false);
  const [moduloSeleccionado, setModuloSeleccionado] = useState(null);
  const [leccionSeleccionada, setLeccionSeleccionada] = useState(null);
  const [certificacionGlobal, setCertificacionGlobal] = useState(0);
  const [horasDedicadas, setHorasDedicadas] = useState(0);
  const [controlesValidados, setControlesValidados] = useState(0);
  const [error, setError] = useState(null);

  // Cargar el plan de estudios desde el backend
  const cargarPlanEstudio = async () => {
    try {
      setLoading(true);
      setError(null);
      // Apunta a tu ruta en FastAPI (se asume proxy configurado o misma IP/puerto)
      const response = await fetch('/api/v1/academia/modulos');
      if (!response.ok) throw new Error('No se pudo sincronizar la malla perimetral de la academia.');
      
      const data = await response.json();
      setModulos(data.modulos || []);
      setCertificacionGlobal(data.certificacion_global || 0);
      setHorasDedicadas(data.horas_dedicadas || 0);
      setControlesValidados(data.controles_validados || 0);
      
      // Auto-seleccionar primer módulo si no hay ninguno seleccionado
      if (data.modulos && data.modulos.length > 0 && !moduloSeleccionado) {
        setModuloSeleccionado(data.modulos[0]);
        if (data.modulos[0].lecciones && data.modulos[0].lecciones.length > 0) {
          setLeccionSeleccionada(data.modulos[0].lecciones[0]);
        }
      }
    } catch (err) {
      console.error(err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    cargarPlanEstudio();
  }, []);

  // 🌟 CONTROLADOR DE DESCARGA VINCULADO AL ENDPOINT EN Python (main.py)
  const handleDownloadDocument = () => {
    try {
      setDownloading(true);
      
      // Construimos el anclaje nativo en memoria para forzar la descarga binaria
      const link = document.createElement('a');
      
      // URL relativa que procesará el decorador @app.get de FastAPI
      // NOTA: Si usas puertos cruzados sin proxy, usa 'http://localhost:7860/api/v1/academia/descargar-norma'
      link.href = '/api/v1/academia/descargar-norma'; 
      
      link.setAttribute('target', '_blank');
      link.setAttribute('download', 'NIST_SP_800-53_Rev5_Official.pdf');
      
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
    } catch (err) {
      console.error("🚨 Error llamando al endpoint de descarga en Python:", err.message);
      alert("Error de comunicación perimetral: No se pudo obtener la norma del backend.");
    } finally {
      // Retardo para normalizar visualmente el botón
      setTimeout(() => setDownloading(false), 1000);
    }
  };

  // Marcar checkpoint / lección como aprobada
  const marcarLeccionCompletada = async (moduloId, leccionId) => {
    try {
      const response = await fetch('/api/v1/academia/completar-leccion', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          modulo_id: moduloId,
          leccion_id: leccionId,
          correcta: true
        })
      });

      if (response.ok) {
        // Refrescamos la UI localmente para sincronizar el ledger inmutable
        cargarPlanEstudio();
      } else {
        alert("Fallo en la validación del checkpoint reglamentario.");
      }
    } catch (err) {
      console.error("Error al registrar checkpoint:", err);
    }
  };

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[500px] text-slate-400">
        <Loader2 className="w-10 h-10 animate-spin text-emerald-500 mb-4" />
        <p className="text-sm tracking-wider font-mono">SINCRONIZANDO CONTROLES FEDERALES NIST...</p>
      </div>
    );
  }

  return (
    <div className="p-6 bg-slate-950 text-slate-100 min-h-screen font-sans">
      {/* HEADER DE LA ACADEMIA */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center border-b border-slate-800 pb-6 mb-6 gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight bg-gradient-to-r from-emerald-400 to-cyan-400 bg-clip-text text-transparent flex items-center gap-2">
            <BookOpen className="w-6 h-6 text-emerald-400" /> Hyperion NIST Academy
          </h1>
          <p className="text-slate-400 text-sm mt-1">Módulo de capacitación reglamentaria y cumplimiento federal institucional.</p>
        </div>

        {/* BOTÓN UNIFICADO DE DESCARGA DIRECTA */}
        <button
          onClick={handleDownloadDocument}
          disabled={downloading}
          className="flex items-center gap-2 px-4 py-2 bg-slate-900 border border-slate-700 hover:border-emerald-500 text-slate-200 hover:text-emerald-400 rounded-lg text-sm transition-all shadow-md font-medium disabled:opacity-50 disabled:pointer-events-none"
        >
          {downloading ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin text-emerald-400" />
              <span>Transmitiendo PDF...</span>
            </>
          ) : (
            <>
              <Download className="w-4 h-4" />
              <span>REGULA_PDF_DOC (Norma Oficial)</span>
            </>
          )}
        </button>
      </div>

      {error && (
        <div className="mb-6 p-4 bg-red-950/40 border border-red-800 rounded-lg flex items-center gap-3 text-red-400 text-sm">
          <ShieldAlert className="w-5 h-5 flex-shrink-0" />
          <div className="flex-1">{error}</div>
          <button onClick={cargarPlanEstudio} className="p-1 hover:bg-red-900/30 rounded">
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* MÉTRICAS DE CUMPLIMIENTO */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
        <div className="bg-slate-900/60 border border-slate-800 p-4 rounded-xl flex items-center gap-4">
          <div className="p-3 bg-emerald-500/10 rounded-lg text-emerald-400">
            <Award className="w-6 h-6" />
          </div>
          <div>
            <div className="text-2xl font-bold font-mono">{certificacionGlobal}%</div>
            <div className="text-xs text-slate-400 uppercase tracking-wider font-medium">Progreso Global</div>
          </div>
        </div>

        <div className="bg-slate-900/60 border border-slate-800 p-4 rounded-xl flex items-center gap-4">
          <div className="p-3 bg-cyan-500/10 rounded-lg text-cyan-400">
            <Clock className="w-6 h-6" />
          </div>
          <div>
            <div className="text-2xl font-bold font-mono">{horasDedicadas} hrs</div>
            <div className="text-xs text-slate-400 uppercase tracking-wider font-medium">Tiempo de Instrucción</div>
          </div>
        </div>

        <div className="bg-slate-900/60 border border-slate-800 p-4 rounded-xl flex items-center gap-4">
          <div className="p-3 bg-purple-500/10 rounded-lg text-purple-400">
            <CheckCircle2 className="w-6 h-6" />
          </div>
          <div>
            <div className="text-2xl font-bold font-mono">{controlesValidados} / 5</div>
            <div className="text-xs text-slate-400 uppercase tracking-wider font-medium">Controles Validados</div>
          </div>
        </div>
      </div>

      {/* DISEÑO EN DOS COLUMNAS: MALLA E INSTRUCTOR */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* COLUMNA IZQUIERDA: LISTADO DE MÓDULOS Y LECCIONES */}
        <div className="lg:col-span-1 space-y-4">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-400 mb-2">Plan de Instrucción</h2>
          
          {modulos.map((mod) => (
            <div 
              key={mod.id} 
              className={`bg-slate-900/40 border rounded-xl overflow-hidden transition-all ${moduloSeleccionado?.id === mod.id ? 'border-emerald-500/50 shadow-md shadow-emerald-950/20' : 'border-slate-800'}`}
            >
              <div 
                onClick={() => setModuloSeleccionado(mod)}
                className="p-4 cursor-pointer hover:bg-slate-900/80 transition-colors"
              >
                <div className="flex justify-between items-start gap-2">
                  <span className="text-xs font-mono font-bold text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded">
                    {mod.norma.split(' ')[0]}
                  </span>
                  <span className="text-xs font-mono text-slate-400">{mod.progreso}% completado</span>
                </div>
                <h3 className="text-sm font-bold text-slate-200 mt-2 line-clamp-1">{mod.titulo}</h3>
                <p className="text-xs text-slate-400 mt-1 line-clamp-2">{mod.descripcion}</p>
              </div>

              {/* Lecciones desplegadas si el módulo está seleccionado */}
              {moduloSeleccionado?.id === mod.id && (
                <div className="bg-slate-950/60 border-t border-slate-900 p-2 space-y-1">
                  {mod.lecciones?.map((lec) => (
                    <div
                      key={lec.id}
                      onClick={() => setLeccionSeleccionada(lec)}
                      className={`w-full text-left p-2 rounded-lg flex items-center justify-between gap-3 text-xs cursor-pointer transition-colors ${leccionSeleccionada?.id === lec.id ? 'bg-slate-900 text-emerald-400 font-medium' : 'hover:bg-slate-900/50 text-slate-300'}`}
                    >
                      <div className="flex items-center gap-2 overflow-hidden">
                        {lec.completada ? (
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 flex-shrink-0" />
                        ) : (
                          <PlayCircle className="w-3.5 h-3.5 text-slate-500 flex-shrink-0" />
                        )}
                        <span className="truncate">{lec.titulo}</span>
                      </div>
                      <span className="font-mono text-[10px] text-slate-500 flex-shrink-0">{lec.duracion}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>

        {/* COLUMNA DERECHA: REPRODUCTOR DE CONTENIDO DE LA LECCIÓN */}
        <div className="lg:col-span-2">
          {leccionSeleccionada ? (
            <div className="bg-slate-900/30 border border-slate-800 rounded-xl p-6 h-full flex flex-col justify-between">
              <div>
                <div className="flex justify-between items-center border-b border-slate-800 pb-4 mb-4">
                  <div>
                    <span className="text-[10px] uppercase font-mono tracking-wider text-slate-400">Contenido Técnico Obligatorio</span>
                    <h2 className="text-lg font-bold text-slate-200 mt-0.5">{leccionSeleccionada.titulo}</h2>
                  </div>
                  <div className="flex items-center gap-2 text-xs font-mono text-slate-400 bg-slate-900 px-3 py-1 rounded-full border border-slate-800">
                    <Clock className="w-3.5 h-3.5 text-slate-500" />
                    {leccionSeleccionada.duracion}
                  </div>
                </div>

                {/* CUERPO DEL TEXTO CIENTÍFICO */}
                <div className="prose prose-invert max-w-none text-sm text-slate-300 leading-relaxed space-y-4 whitespace-pre-line bg-slate-950/40 p-4 rounded-xl border border-slate-900 font-mono text-justify">
                  {leccionSeleccionada.contenido}
                </div>
              </div>

              {/* BOTONES DE ACCIÓN DE LA LECCIÓN */}
              <div className="mt-6 pt-4 border-t border-slate-800 flex flex-col sm:flex-row sm:justify-between items-center gap-4">
                <div className="flex items-center gap-2 text-xs text-slate-400">
                  <FileText className="w-4 h-4 text-slate-500" />
                  <span>Control de referencia: <strong className="text-slate-300 font-mono">{moduloSeleccionado?.norma}</strong></span>
                </div>

                {!leccionSeleccionada.completada && (
                  <button
                    onClick={() => marcarLeccionCompletada(moduloSeleccionado.id, leccionSeleccionada.id)}
                    className="w-full sm:w-auto px-5 py-2 bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold rounded-lg text-xs tracking-wider uppercase transition-colors shadow-lg shadow-emerald-950/20 flex items-center justify-center gap-1.5"
                  >
                    <span>Sellar Checkpoint</span>
                    <ChevronRight className="w-4 h-4" />
                  </button>
                )}
                {leccionSeleccionada.completada && (
                  <div className="flex items-center gap-1.5 text-xs text-emerald-400 font-medium bg-emerald-500/10 px-3 py-1.5 rounded-lg border border-emerald-500/20">
                    <CheckCircle2 className="w-4 h-4" />
                    <span>Lección Auditada y Completada</span>
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="bg-slate-900/20 border border-slate-800 border-dashed rounded-xl p-8 flex flex-col items-center justify-center text-center h-full min-h-[300px]">
              <BookOpen className="w-8 h-8 text-slate-600 mb-2" />
              <p className="text-sm text-slate-400 font-medium">Selecciona una directiva o lección en la malla para desplegar los controles técnicos.</p>
            </div>
          )}
        </div>

      </div>
    </div>
  );
}