import React, { useMemo } from 'react';
import { geoPath, geoNaturalEarth1 } from 'd3-geo';
import { feature } from 'topojson-client';
import land from 'world-atlas/land-110m.json';

const WIDTH = 200;
const HEIGHT = 100;

// Proyección + path del contorno mundial se calculan una sola vez (no dependen de las props).
const landFeature = feature(land, land.objects.land);
const projection = geoNaturalEarth1().fitSize([WIDTH, HEIGHT], landFeature);
const pathGenerator = geoPath(projection);
const worldPathD = pathGenerator(landFeature);

const COLORS = {
  CRITICA: '#f87171',
  CRÍTICA: '#f87171',
  ALTA: '#fbbf24',
  MEDIA: '#fbbf24',
  INFO: '#38bdf8',
};

/**
 * points: [{ id, lat, lon, severidad, label }]
 * serverPoint: { lat, lon, label } opcional, marca tu propio servidor
 */
export default function WorldMap({ points = [], serverPoint = null }) {
  const projected = useMemo(() => {
    return points
      .map((p) => {
        if (typeof p.lat !== 'number' || typeof p.lon !== 'number') return null;
        const coords = projection([p.lon, p.lat]);
        if (!coords) return null;
        return { ...p, x: coords[0], y: coords[1] };
      })
      .filter(Boolean);
  }, [points]);

  const serverXY = useMemo(() => {
    if (!serverPoint) return null;
    return projection([serverPoint.lon, serverPoint.lat]);
  }, [serverPoint]);

  return (
    <div className="relative bg-[#05070f] border border-slate-200 dark:border-slate-800 rounded-2xl overflow-hidden">
      <svg viewBox={`0 0 ${WIDTH} ${HEIGHT}`} className="w-full block">
        <path d={worldPathD} fill="#111c33" stroke="#1e293b" strokeWidth="0.3" />

        {serverXY && (
          <>
            {projected.map((p) => (
              <line
                key={`line-${p.id}`}
                x1={p.x}
                y1={p.y}
                x2={serverXY[0]}
                y2={serverXY[1]}
                stroke={COLORS[p.severidad] || COLORS.INFO}
                strokeWidth="0.3"
                strokeDasharray="1,1"
                opacity="0.5"
              />
            ))}
            <circle cx={serverXY[0]} cy={serverXY[1]} r="1.6" fill="#3b82f6">
              <animate attributeName="r" values="1.6;3.5;1.6" dur="2.5s" repeatCount="indefinite" />
              <animate attributeName="opacity" values="0.8;0;0.8" dur="2.5s" repeatCount="indefinite" />
            </circle>
            <circle cx={serverXY[0]} cy={serverXY[1]} r="1.6" fill="#3b82f6" />
          </>
        )}

        {projected.map((p) => {
          const color = COLORS[p.severidad] || COLORS.INFO;
          return (
            <g key={p.id}>
              <circle cx={p.x} cy={p.y} r="1.4" fill={color}>
                <animate attributeName="r" values="1.4;3;1.4" dur="2s" repeatCount="indefinite" />
                <animate attributeName="opacity" values="0.7;0;0.7" dur="2s" repeatCount="indefinite" />
              </circle>
              <circle cx={p.x} cy={p.y} r="1.4" fill={color} />
            </g>
          );
        })}
      </svg>
    </div>
  );
}