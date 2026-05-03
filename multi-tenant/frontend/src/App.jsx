import React, { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Chart as ChartJS, CategoryScale, LinearScale, PointElement, LineElement,
         BarElement, Title, Tooltip, Legend, Filler } from 'chart.js';
import { Line } from 'react-chartjs-2';
import { MapContainer, TileLayer, Marker, Popup, Polyline, CircleMarker, useMap } from 'react-leaflet';
import L from 'leaflet';
import * as THREE from 'three';
import { OrbitControls } from 'three/examples/jsm/controls/OrbitControls';
import html2pdf from 'html2pdf.js';
import * as api from './api/index.js';
import { useWebSocket } from './hooks/useWebSocket.js';
import { AuthProvider, useAuth } from './context/AuthContext.jsx';
import CopilotChat from './components/CopilotChat.jsx';

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement,
  BarElement, Title, Tooltip, Legend, Filler);

// ========== 1. CONSTANTS & HELPERS ==========
const SEV = {
  emergency: '#b91c1c', critical: '#ef4444', high: '#f59e0b',
  medium: '#eab308', low: '#10b981', info: '#d97706', safe: '#10b981'
};
const SevBadge = ({ s }) => <span className={`badge badge-${s}`}>{s}</span>;

// ========== 2. INCIDENT TOAST ==========
// Toasts are state-aware and live as long as their underlying incident.
// Shape: { id, state: 'active' | 'resolved' | 'info', severity, message, sub, threat?, ts }
// - 'active' toasts persist on screen (NO auto-dismiss) until a matching
//   threat:resolved arrives or the user dismisses them.
// - 'resolved' toasts show the green "CLEARED" treatment for ~3.5s then fade.
// - 'info' toasts (non-threat events) auto-dismiss after 6s, like before.
const IncidentToast = ({ toasts, onDismiss }) => (
  <div className="fixed top-4 right-4 z-[9999] space-y-2 w-96 mono pointer-events-none">
    <AnimatePresence>
      {toasts.map(t => {
        const mitigated = t.state === 'mitigated';
        const resolved  = t.state === 'resolved';
        const accent = (mitigated || resolved) ? '#10b981' : (SEV[t.severity] || '#d97706');
        const iconCls = mitigated ? 'fa-shield-halved' : resolved ? 'fa-circle-check' : (t.state === 'info' ? 'fa-circle-info' : 'fa-triangle-exclamation');
        const glow = !mitigated && !resolved && (t.severity === 'critical' || t.severity === 'emergency');
        const label = mitigated ? 'blocked' : resolved ? 'cleared' : (t.severity || 'alert');
        return (
          <motion.div key={t.id}
            layout
            initial={{ opacity: 0, x: 40, scale: 0.96 }}
            animate={{ opacity: 1, x: 0, scale: 1 }}
            exit={{ opacity: 0, x: 60, scale: 0.95 }}
            transition={{ type: 'spring', stiffness: 400, damping: 32 }}
            className="panel p-3 pl-4 cursor-pointer flex items-start gap-3 border-l-2 pointer-events-auto"
            style={{
              borderLeftColor: accent,
              boxShadow: glow ? `0 0 0 1px ${accent}30, 0 8px 32px ${accent}20` : (mitigated ? `0 0 0 1px ${accent}40, 0 8px 32px ${accent}30` : undefined),
              background: (mitigated || resolved) ? 'linear-gradient(90deg, #10b98112 0%, #10101280 100%)' : undefined,
            }}
            onClick={() => onDismiss(t.id)}>
            <i className={`fas ${iconCls} text-[14px] mt-0.5`} style={{ color: accent }} />
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2">
                <span className="text-[9px] tracking-[0.18em] uppercase font-bold" style={{ color: accent }}>
                  {label}
                </span>
                {!mitigated && !resolved && t.state === 'active' && (
                  <span className="w-1.5 h-1.5 rounded-full animate-pulse" style={{ background: accent }} />
                )}
                {mitigated && t.mitigation?.action && (
                  <span className="text-[9px] mono px-1.5 py-0.5 rounded" style={{ background: '#10b98115', color: '#34d399', border: '1px solid #10b98140' }}>{t.mitigation.action}</span>
                )}
              </div>
              <div className="text-[12px] text-[#e4e4e7] leading-snug mt-0.5">{t.message}</div>
              {t.sub && <div className="text-[9px] text-[#71717a] mt-0.5">{t.sub}</div>}
              {mitigated && t.mitigation?.technique && (
                <div className="text-[9px] mono text-emerald-500/80 mt-0.5">defender · {t.mitigation.technique} · score {t.mitigation.defender_score}</div>
              )}
            </div>
            <button
              className="text-[#52525b] hover:text-[#e4e4e7] text-[10px] leading-none mt-0.5 px-1"
              onClick={(e) => { e.stopPropagation(); onDismiss(t.id); }}>
              ×
            </button>
          </motion.div>
        );
      })}
    </AnimatePresence>
  </div>
);

// ========== 2b. ACTIVE INCIDENT BANNER ==========
// Sticky top-of-content banner that surfaces while ANY active incident is
// in flight. Hides automatically at zero. Click to jump to threats page.
const SEV_RANK = { emergency: 0, critical: 1, high: 2, medium: 3, low: 4, info: 5, safe: 6 };
const ActiveIncidentBanner = ({ activeThreats, onJump }) => {
  const count = activeThreats.length;
  if (count === 0) return null;
  const worst = activeThreats.reduce((a, t) => (SEV_RANK[t.severity] < SEV_RANK[a.severity] ? t : a), activeThreats[0]);
  const accent = SEV[worst.severity] || '#ef4444';
  return (
    <motion.button
      type="button"
      onClick={onJump}
      initial={{ opacity: 0, y: -10 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -10 }}
      className="w-full mb-4 px-4 py-2.5 rounded-sm flex items-center gap-3 text-left border"
      style={{ borderColor: `${accent}55`, background: `${accent}10`, boxShadow: `0 0 24px ${accent}20` }}>
      <span className="relative flex h-2.5 w-2.5">
        <span className="animate-ping absolute inline-flex h-full w-full rounded-full opacity-60" style={{ background: accent }} />
        <span className="relative inline-flex rounded-full h-2.5 w-2.5" style={{ background: accent }} />
      </span>
      <div className="flex-1 min-w-0 mono">
        <span className="text-[11px] font-bold tracking-[0.2em] uppercase" style={{ color: accent }}>
          {count} active {count === 1 ? 'breach' : 'breaches'}
        </span>
        <span className="text-[10px] text-[#a1a1aa] ml-3">
          worst: {worst.severity} · {worst.threat_type}{worst.icao24 ? ` · ${worst.icao24}` : ''}
        </span>
      </div>
      <span className="text-[9px] mono text-[#71717a] tracking-widest">VIEW →</span>
    </motion.button>
  );
};

// ========== 2c. NOTIFICATION BELL ==========
// Top-bar bell with unread count + dropdown showing the rolling history of
// incidents (active + resolved). Resolved entries get the green pip; active
// entries pulse. Mirrors the toast deck but persists across navigations.
const NotificationBell = ({ history, unread, onOpen, isOpen, onClear, onJump }) => (
  <div className="relative">
    <button
      onClick={onOpen}
      className="relative w-9 h-9 flex items-center justify-center rounded-sm border border-[#27272a] bg-[#101012] text-[#a1a1aa] hover:text-[#e4e4e7] hover:border-[#3f3f46] transition-all"
      title="Incidents">
      <i className="fas fa-bell text-[12px]" />
      {unread > 0 && (
        <span className="absolute -top-1 -right-1 min-w-[16px] h-[16px] px-1 rounded-full text-[9px] mono font-bold flex items-center justify-center bg-[#b91c1c] text-white border border-[#0a0a0b]">
          {unread > 99 ? '99+' : unread}
        </span>
      )}
    </button>
    <AnimatePresence>
      {isOpen && (
        <motion.div
          initial={{ opacity: 0, y: -8, scale: 0.96 }}
          animate={{ opacity: 1, y: 0, scale: 1 }}
          exit={{ opacity: 0, y: -8, scale: 0.96 }}
          transition={{ duration: 0.15 }}
          className="absolute right-0 mt-2 w-96 panel z-[9998] overflow-hidden">
          <div className="flex items-center justify-between px-4 py-3 border-b border-[#27272a]">
            <span className="text-[10px] mono tracking-[0.2em] uppercase text-[#a1a1aa]">Incidents</span>
            {history.length > 0 && (
              <button onClick={onClear} className="text-[9px] mono text-[#71717a] hover:text-[#e4e4e7] uppercase tracking-wider">Clear</button>
            )}
          </div>
          <div className="max-h-96 overflow-y-auto">
            {history.length === 0 && (
              <div className="px-4 py-8 text-center text-[10px] mono text-[#52525b] uppercase tracking-wider">
                <i className="fas fa-shield-check text-[24px] block mb-2 opacity-30" />
                no incidents
              </div>
            )}
            {history.map(item => {
              const accent = item.state === 'resolved' ? '#10b981' : (SEV[item.severity] || '#d97706');
              return (
                <button key={item.id} onClick={() => onJump(item)}
                  className="w-full flex items-start gap-3 px-4 py-3 border-b border-[#1c1c20] hover:bg-[#161618] text-left transition-colors">
                  <div className="w-1 self-stretch rounded-full" style={{ background: accent }} />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-[9px] mono uppercase tracking-[0.15em] font-bold" style={{ color: accent }}>
                        {item.state === 'resolved' ? '✓ resolved' : item.severity || 'alert'}
                      </span>
                      <span className="text-[9px] mono text-[#52525b]">
                        {new Date(item.ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                      </span>
                    </div>
                    <div className="text-[11px] text-[#e4e4e7] mt-0.5 truncate">{item.message}</div>
                    {item.sub && <div className="text-[9px] text-[#71717a] mt-0.5 truncate">{item.sub}</div>}
                  </div>
                </button>
              );
            })}
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  </div>
);

// ========== 3. METRIC CARD ==========
const MCard = ({ label, value, icon, color, sub }) => (
  <motion.div whileHover={{ y: -1 }} className="panel p-5 overflow-hidden group">
    <div className="absolute top-0 right-0 p-1 opacity-10">
      <i className={`fas fa-${icon} text-4xl mr-[-10px] mt-[-10px]`} style={{ color }} />
    </div>
    <div className="flex items-center justify-between mb-4 border-b border-[#27272a] pb-2">
      <span className="text-[9px] mono text-[#71717a] tracking-[0.2em] uppercase flex items-center gap-2">
        <span className="w-1 h-3 bg-current" style={{ backgroundColor: color }}></span>
        {label}
      </span>
      <div className="mono text-[10px] text-[#52525b] group-hover:text-[#a1a1aa]">00x{Math.floor(Math.random()*100)}</div>
    </div>
    <div className="text-3xl mono font-bold tracking-tighter" style={{ color }}>{value ?? 0}</div>
    {sub && <div className="text-[9px] mono text-[#52525b] mt-2 uppercase tracking-wide opacity-80">{sub}</div>}
  </motion.div>
);

// ========== 4. SIDEBAR ==========
const NAV = [
  { id: 'dashboard', icon: 'gauge-high', label: 'Dashboard' },
  { id: 'map', icon: 'map', label: 'Live Map' },
  { id: 'assets', icon: 'plane', label: 'Fleet & Assets' },
  { id: 'threats', icon: 'skull-crossbones', label: 'Threats' },
  { id: 'redteam', icon: 'dna', label: 'SEART AI' },
  { id: 'alerts', icon: 'bell', label: 'Alerts' },
  { id: 'reports', icon: 'file-contract', label: 'Reports' },
  { id: 'audit', icon: 'shield-check', label: 'Audit Log' },
];

const Sidebar = ({ page, setPage, user, logout, unacked }) => (
  <aside className="fixed left-0 top-0 bottom-0 flex flex-col z-40 bg-[#0a0a0b]" style={{ width: 220, borderRight: '1px solid #27272a' }}>
    <div className="px-5 py-6 border-b border-[#27272a] bg-[#101012]">
      <div className="flex items-center gap-3 mb-1">
        <div className="w-8 h-8 rounded-sm flex items-center justify-center flex-shrink-0 bg-[#0a0a0b] border border-[#3f3f46]">
          <i className="fas fa-shield-halved text-[10px] text-[#d97706]" />
        </div>
        <div>
          <span className="font-display font-black text-xs text-[#e4e4e7] tracking-[0.25em] uppercase">Shadow_Kernel</span>
          <div className="text-[8px] mono text-[#71717a] tracking-normal">SYS_VERSION: 11.0_PRO</div>
        </div>
      </div>
    </div>
    
    <nav className="flex-1 p-4 space-y-1 overflow-y-auto">
      <div className="text-[9px] mono text-[#52525b] px-3 mb-2 uppercase tracking-[0.2em]">Nav_Dir</div>
      {NAV.map(({ id, icon, label }) => (
        <button key={id} onClick={() => setPage(id)}
          className={`w-full flex items-center gap-4 px-3 py-2 rounded-sm text-[11px] mono transition-all duration-100 uppercase relative group ${page === id ? 'text-[#d97706]' : 'text-[#71717a] hover:text-[#e4e4e7] hover:bg-[#161618]'}`}
          style={page === id ? { background: 'rgba(217,119,6,0.05)', border: '1px solid rgba(217,119,6,0.15)' } : {}}>
          <i className={`fas fa-${icon} w-4 text-[10px] opacity-70 group-hover:opacity-100`} />
          <span className="tracking-tighter">{label}</span>
          {page === id && <span className="ml-auto text-[10px] opacity-100">_</span>}
          {id === 'alerts' && unacked > 0 && (
            <span className="ml-auto text-[9px] px-1.5 py-0.5 rounded-sm bg-[#b91c1c] text-white animate-pulse">
              {unacked}
            </span>
          )}
        </button>
      ))}
    </nav>
    
    <div className="p-4 border-t border-[#27272a] bg-[#0a0a0b]">
      <div className="flex items-center gap-3 px-3 py-3 rounded-sm bg-[#101012] border border-[#27272a]">
        <div className="w-8 h-8 rounded-sm flex items-center justify-center flex-shrink-0 text-[11px] font-bold bg-[#0a0a0b] border border-[#27272a] text-[#a1a1aa] mono">
          {user?.username?.[0]?.toUpperCase()}
        </div>
        <div className="flex-1 min-w-0">
          <div className="text-[11px] text-[#e4e4e7] truncate mono">{user?.username}</div>
          <div className="text-[9px] mono text-[#52525b] uppercase">{user?.role}</div>
        </div>
        <button onClick={logout} title="TERM_LOGOUT" className="w-6 h-6 flex items-center justify-center rounded-sm bg-[#1c1c20] border border-[#3f3f46] text-[#71717a] hover:text-[#ef4444] hover:border-[#b91c1c] transition-all">
          <i className="fas fa-power-off text-[10px]" />
        </button>
      </div>
    </div>
  </aside>
);

// ========== 5. FORECAST CHART ==========
const ForecastChart = ({ timeline }) => {
  const [forecast, setForecast] = useState([]);
  useEffect(() => {
    if (!timeline || timeline.length < 3) return;
    const counts = timeline.map(d => d.count);
    const last = counts[counts.length - 1];
    const slope = (counts[counts.length - 1] - counts[counts.length - 2]) || 0;
    const future = [last, last + slope, last + slope * 2, last + slope * 3].map(v => Math.max(0, Math.round(v)));
    setForecast(future);
  }, [timeline]);
  const labels = [...(timeline || []).map(d => new Date(d.hour).toLocaleTimeString([], { hour: '2-digit' })), '+1h', '+2h', '+3h'];
  const data = {
    labels,
    datasets: [
      { label: 'Actual', data: (timeline || []).map(d => d.count), borderColor: '#d97706', borderWidth: 2, fill: false, pointRadius: 3 },
      { label: 'AI Forecast', data: [...(timeline || []).slice(-1).map(d => d.count), ...forecast], borderColor: '#d97706', borderDash: [5, 5], fill: false, pointRadius: 2 }
    ]
  };
  return (
    <div className="panel p-4 mt-4">
      <div className="flex items-center justify-between mb-3">
        <span className="text-[10px] mono text-s-accent tracking-widest uppercase">AI Threat Forecast (next 3 hours)</span>
        <span className="text-[9px] mono text-gray-600">Powered by Gemini</span>
      </div>
      <div style={{ height: 160 }}><Line data={data} options={{ responsive: true, maintainAspectRatio: false, plugins: { legend: { labels: { color: '#9ca3af' } } }, scales: { x: { ticks: { color: '#6b7280' } }, y: { ticks: { color: '#6b7280' } } } }} /></div>
    </div>
  );
};

// ========== 6. DASHBOARD ==========
const Dashboard = ({ data }) => {
  if (!data) return null;
  const { threats, assets, alerts, topAttacks, riskTop, timeline, recentAlerts } = data;
  const labels = (timeline || []).map(d => new Date(d.hour).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }));
  const chartData = {
    labels,
    datasets: [
      { label: 'All', data: (timeline || []).map(d => d.count), borderColor: '#d97706', backgroundColor: 'rgba(217,119,6,.08)', fill: true, tension: .4, pointRadius: 3, borderWidth: 1.5 },
      { label: 'Crit', data: (timeline || []).map(d => d.critical), borderColor: '#b91c1c', backgroundColor: 'rgba(185,28,28,.06)', fill: true, tension: .4, pointRadius: 3, borderWidth: 1.5 },
    ]
  };
  return (
    <div id="report-pdf-content">
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <MCard label="Active Threats" value={threats?.active} icon="skull-crossbones" color="#b91c1c" sub={`${threats?.total || 0} total / 24h`} />
        <MCard label="Critical" value={threats?.critical} icon="radiation" color="#d97706" sub={`avg score ${parseFloat(threats?.avg_score || 0).toFixed(2)}`} />
        <MCard label="Fleet Online" value={assets?.active} icon="plane" color="#10b981" sub={`${assets?.under_attack || 0} under attack`} />
        <MCard label="Unacked Alerts" value={alerts?.unacked} icon="bell" color="#eab308" sub="last 6 hours" />
      </div>
      <div className="grid grid-cols-5 gap-4 mt-5">
        <div className="col-span-3 panel p-5" style={{ height: 240 }}>
          <h3 className="text-[10px] mono text-s-accent tracking-widest uppercase mb-4">Threat Timeline – 12h</h3>
          <div style={{ height: 180 }}><Line data={chartData} options={{ responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false }, tooltip: { backgroundColor: '#161618', borderColor: '#27272a', borderWidth: 1, titleColor: '#d97706', bodyColor: '#9ca3af' } }, scales: { x: { ticks: { color: '#374151', font: { family: 'Share Tech Mono', size: 10 } }, grid: { color: '#27272a' } }, y: { ticks: { color: '#374151', font: { family: 'Share Tech Mono', size: 10 } }, grid: { color: '#27272a' } } } }} /></div>
        </div>
        <div className="col-span-2 panel p-5">
          <h3 className="text-[10px] mono text-s-accent tracking-widest uppercase mb-4">Risk Leaderboard</h3>
          <div className="space-y-3">
            {(riskTop || []).map((r, i) => (
              <div key={i} className="flex items-center gap-3">
                <span className="mono text-xs text-gray-600 w-3">{i + 1}</span>
                <div className="flex-1 min-w-0">
                  <div className="text-xs text-gray-300 truncate">{r.entity_name}</div>
                  <div className="text-[10px] text-gray-600 truncate mono">{(r.threat_types || []).join(', ')}</div>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-14 h-1 rounded-full bg-s-border overflow-hidden">
                    <div className="h-full rounded-full" style={{ width: `${r.risk_score}%`, background: r.risk_score > 80 ? '#b91c1c' : r.risk_score > 60 ? '#d97706' : '#eab308' }} />
                  </div>
                  <span className="mono text-xs font-semibold" style={{ color: r.risk_score > 80 ? '#ef4444' : r.risk_score > 60 ? '#f59e0b' : '#eab308' }}>
                    {parseFloat(r.risk_score).toFixed(0)}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
      <div className="grid grid-cols-2 gap-4 mt-5">
        <div className="panel p-5">
          <h3 className="text-[10px] mono text-s-accent tracking-widest uppercase mb-4">Attack Families – 24h</h3>
          <div className="space-y-3">
            {(topAttacks || []).map((a, i) => {
              const max = Math.max(...(topAttacks || []).map(x => x.count), 1);
              return (
                <div key={i}>
                  <div className="flex justify-between text-xs mb-1">
                    <span className="text-gray-400">{a.threat_type}</span>
                    <span className="mono text-s-accent">{a.count}</span>
                  </div>
                  <div className="h-1.5 rounded-full bg-s-border overflow-hidden">
                    <motion.div className="h-full rounded-full" initial={{ width: 0 }} animate={{ width: `${(a.count / max) * 100}%` }} transition={{ delay: i * .04, duration: .5 }} style={{ background: 'linear-gradient(90deg,#d97706,#52525b)' }} />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
        <div className="panel p-5">
          <h3 className="text-[10px] mono text-s-accent tracking-widest uppercase mb-4">Recent Alerts</h3>
          <div className="space-y-2 overflow-y-auto" style={{ maxHeight: 220 }}>
            {(recentAlerts || []).map(a => (
              <div key={a.id} className="flex items-start gap-2.5 border-b border-s-border/40 pb-2">
                <div className="w-1.5 h-1.5 rounded-full mt-1.5 flex-shrink-0" style={{ background: SEV[a.severity] || '#d97706' }} />
                <div className="flex-1 min-w-0">
                  <div className="text-xs text-gray-300 leading-snug truncate">{a.title}</div>
                  <div className="text-[10px] mono text-gray-600">{a.aircraft_name} · {new Date(a.detected_at).toLocaleTimeString()}</div>
                </div>
                <SevBadge s={a.severity} />
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

// ========== 7. ASSETS PAGE (ללא כפילויות + מיון) ==========
const AssetsPage = ({ assets, user, selectedAsset, onClearSelected, onIsolate }) => {
  const [sel, setSel] = useState(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    if (selectedAsset) setSel(selectedAsset);
  }, [selectedAsset]);

  const uniqueAssets = useMemo(() => {
    const map = new Map();
    (assets || []).forEach(a => {
      const key = `${a.icao24 || a.name}`;
      if (!map.has(key) || a.id > map.get(key).id) map.set(key, a);
    });
    return Array.from(map.values());
  }, [assets]);

  const threatOrder = { critical: 0, high: 1, medium: 2, low: 3, safe: 4, info: 5 };
  const sortedAssets = [...uniqueAssets].sort((a,b) => (threatOrder[a.threat_level] || 99) - (threatOrder[b.threat_level] || 99));

  if (!sortedAssets.length) {
    return (
      <div className="panel p-5">
        <h2 className="text-[10px] mono text-s-accent tracking-widest uppercase mb-5">Fleet & Assets</h2>
        <div className="text-center text-gray-500 py-10">No aircraft found. Please add aircraft via PostgreSQL.</div>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="panel p-5">
        <h2 className="text-[10px] mono text-s-accent tracking-widest uppercase mb-5">Fleet & Assets – {user?.tenant_name || 'All'}</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-s-border text-gray-600 mono">
                {['Name', 'ICAO24', 'Callsign', 'Status', 'Threat', 'Altitude', 'Speed', 'Squawk', 'Protected'].map(h => <th key={h} className="text-left pb-2 pr-4 font-normal">{h}</th>)}
                </tr>
            </thead>
            <tbody className="divide-y divide-s-border/20">
              {sortedAssets.map(a => (
                <tr key={a.id} onClick={() => setSel(a)} className="hover:bg-s-border/10 transition-colors cursor-pointer">
                  <td className="py-2.5 pr-4 text-gray-300 font-medium">{a.name}</td>
                  <td className="py-2.5 pr-4 mono text-gray-500">{a.icao24 || '–'}</td>
                  <td className="py-2.5 pr-4 mono text-gray-500">{a.callsign || '–'}</td>
                  <td className="py-2.5 pr-4"><SevBadge s={a.status} /></td>
                  <td className="py-2.5 pr-4"><span className={`badge badge-${a.threat_level}`}>{a.threat_level}</span></td>
                  <td className="py-2.5 pr-4 mono text-gray-600">{a.altitude_ft?.toLocaleString() || '–'}</td>
                  <td className="py-2.5 pr-4 mono text-gray-600">{a.speed_kts || '–'}</td>
                  <td className="py-2.5 pr-4 mono text-gray-600">{a.squawk || '–'}</td>
                  <td className="py-2.5">{a.is_protected ? <span style={{ color: '#10b981' }}>✓</span> : <span style={{ color: '#ef4444' }}>✗</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
      <AnimatePresence>
        {sel && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/70 z-50 flex items-end sm:items-center justify-center p-4" onClick={() => { setSel(null); onClearSelected?.(); }}>
            <motion.div initial={{ y: 40, opacity: 0 }} animate={{ y: 0, opacity: 1 }} exit={{ y: 40, opacity: 0 }}
              className="panel p-6 w-full max-w-xl max-h-[80vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
              <div className="flex items-start justify-between mb-5">
                <div>
                  <h3 className="font-display font-bold text-xl text-gradient">{sel.name}</h3>
                  <div className="mono text-xs text-gray-500 mt-0.5">ICAO: {sel.icao24} · {sel.registration}</div>
                </div>
                <button onClick={() => { setSel(null); onClearSelected?.(); }} className="text-gray-500 hover:text-white transition-colors"><i className="fas fa-xmark" /></button>
              </div>
              <div className="grid grid-cols-2 gap-4 text-xs mb-5">
                {[
                  ['Threat Level', <span className={`badge badge-${sel.threat_level}`}>{sel.threat_level}</span>],
                  ['Status', <SevBadge s={sel.status} />],
                  ['Altitude', `${sel.altitude_ft?.toLocaleString() || '–'} ft`],
                  ['Speed', `${sel.speed_kts || '–'} kts`],
                  ['Heading', `${sel.heading || '–'}°`],
                  ['Squawk', sel.squawk || '–'],
                  ['Location', sel.location || '–'],
                  ['Protected', sel.is_protected ? '✓ Yes' : '✗ No'],
                  ['Criticality', `${Math.round((sel.criticality || 0) * 100)}%`],
                ].map(([l, v], i) => (
                  <div key={i} className="bg-s-void rounded-lg p-3" style={{ border: '1px solid #27272a' }}>
                    <div className="text-gray-600 mono text-[10px] uppercase tracking-wider mb-1">{l}</div>
                    <div className="text-gray-200">{v}</div>
                  </div>
                ))}
              </div>
              {sel.latitude && sel.longitude && (
                <div className="mt-2 rounded-lg overflow-hidden border border-s-border" style={{ height: 150 }}>
                  <MapContainer center={[sel.latitude, sel.longitude]} zoom={10} style={{ height: '100%', width: '100%' }} scrollWheelZoom={false}>
                    <TileLayer url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png" />
                    <Marker position={[sel.latitude, sel.longitude]} />
                  </MapContainer>
                </div>
              )}
              {onIsolate && (user?.role === 'admin' || user?.role === 'analyst' || user?.role === 'superadmin') && (
                <div className="mt-5 flex gap-2 justify-end">
                  <button
                    disabled={busy}
                    onClick={async () => {
                      const isolating = sel.status !== 'compromised';
                      setBusy(true);
                      try {
                        await onIsolate(sel, isolating);
                        setSel({ ...sel, status: isolating ? 'compromised' : 'active' });
                      } finally {
                        setBusy(false);
                      }
                    }}
                    className={`text-[11px] mono px-3 py-1.5 rounded border transition-colors ${
                      sel.status === 'compromised'
                        ? 'border-emerald-500/40 text-emerald-400 hover:bg-emerald-500/10'
                        : 'border-rose-500/40 text-rose-400 hover:bg-rose-500/10'
                    } disabled:opacity-50`}
                  >
                    <i className={`fas ${sel.status === 'compromised' ? 'fa-link' : 'fa-link-slash'} mr-2`} />
                    {sel.status === 'compromised' ? 'Restore Asset' : 'Isolate Asset'}
                  </button>
                </div>
              )}
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

// ========== 8. THREATS PAGE ==========
const ThreatsPage = ({ threats, onUpdateStatus }) => {
  const [filter, setFilter] = useState('all');
  const filtered = useMemo(() => {
    if (filter === 'all') return threats;
    if (filter === 'active') return threats.filter(t => t.status === 'active');
    if (filter === 'critical') return threats.filter(t => t.severity === 'critical' || t.severity === 'emergency');
    return threats;
  }, [threats, filter]);
  return (
    <div className="panel p-5">
      <div className="flex justify-between items-center mb-5">
        <h2 className="text-[10px] mono text-s-accent tracking-widest uppercase">All Threats</h2>
        <div className="flex gap-2">
          {['all','active','critical'].map(f => (
            <button key={f} onClick={() => setFilter(f)} className={`text-[10px] mono px-2 py-1 rounded ${filter === f ? 'bg-s-accent/20 text-s-accent border border-s-accent/30' : 'text-gray-500 border border-s-border'}`}>{f}</button>
          ))}
        </div>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-s-border text-gray-600 mono">
              {['Time', 'Type', 'Sev', 'Aircraft', 'Score', 'MITRE', 'Status', 'Action'].map(h => <th key={h} className="text-left pb-2 pr-4 font-normal">{h}</th>)}
            </tr>
          </thead>
          <tbody className="divide-y divide-s-border/20">
            {(filtered || []).map(t => (
              <tr key={t.id} className="hover:bg-s-border/10 transition-colors">
                <td className="py-2.5 pr-4 mono text-gray-600">{new Date(t.detected_at).toLocaleTimeString()}</td>
                <td className="py-2.5 pr-4 text-gray-300">{t.threat_type}</td>
                <td className="py-2.5 pr-4"><SevBadge s={t.severity} /></td>
                <td className="py-2.5 pr-4 text-gray-500 max-w-[120px] truncate">{t.aircraft_name || t.icao24 || '–'}</td>
                <td className="py-2.5 pr-4 mono" style={{ color: t.score > 0.8 ? '#b91c1c' : t.score > 0.6 ? '#d97706' : '#eab308' }}>{parseFloat(t.score || 0).toFixed(3)}</td>
                <td className="py-2.5 pr-4 mono text-gray-600">{t.mitre_technique || '–'}</td>
                <td className="py-2.5 pr-4"><span className={`badge badge-${t.status === 'active' ? 'critical' : 'info'}`}>{t.status}</span></td>
                <td className="py-2.5">
                  {t.status === 'active' && (
                    <button onClick={() => onUpdateStatus(t.id, 'investigating')}
                      className="text-[10px] mono px-2 py-1 rounded border border-s-border hover:border-s-accent/40 text-gray-500 hover:text-s-accent transition-colors">
                      Investigate
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

// ========== 8b. SEART (Generative Red-Team) PAGE ==========
// Shows the live evolutionary cycle: current generation, the 8 attack genomes
// in flight, their lineage, and the rising mean-fitness curve as the AI
// sharpens its synthetic attacks against our defenses.
const FAMILY_COLOR = {
  spoofing: '#ef4444', jamming: '#d97706', replay: '#a855f7', meaconing: '#22d3ee',
  deauth: '#84cc16', mitm: '#ec4899', protocol_fuzz: '#06b6d4',
  side_channel: '#f59e0b', covert_channel: '#10b981', rf_overpower: '#f97316',
};

const SeartPage = ({ user, status, onPause, onFire, busy }) => {
  if (!status) {
    return (
      <div className="panel p-5">
        <div className="text-[10px] mono text-s-accent tracking-widest uppercase mb-4">SEART · Synthetic Evolving Adversarial Red-Team</div>
        <div className="text-xs text-gray-500">Initializing generative engine…</div>
      </div>
    );
  }
  const canControl = user?.role === 'admin' || user?.role === 'superadmin';
  const histMax = Math.max(0.001, ...(status.history || []).map(h => h.bestFitness || 0));
  return (
    <div className="space-y-4">
      <div className="panel p-5">
        <div className="flex items-start justify-between mb-5">
          <div>
            <div className="text-[10px] mono text-s-accent tracking-widest uppercase">SEART · Generative Red-Team</div>
            <div className="font-display font-bold text-xl text-gradient mt-1">Generation #{status.generation}</div>
            <div className="text-[10px] mono text-gray-500 mt-1">
              {status.popSize} live genomes · {status.totalFired} fired · {status.totalSlipped} slipped past defenses
            </div>
          </div>
          {canControl && (
            <div className="flex gap-2">
              <button
                disabled={busy}
                onClick={() => onPause(!status.paused)}
                className={`text-[10px] mono px-3 py-1.5 rounded-sm border uppercase tracking-wider transition-all flex items-center gap-2 disabled:opacity-50 ${status.paused ? 'border-emerald-500/40 text-emerald-400 hover:bg-emerald-500/10' : 'border-amber-500/40 text-amber-400 hover:bg-amber-500/10'}`}>
                <i className={`fas ${status.paused ? 'fa-play' : 'fa-pause'} text-[10px]`} />
                {status.paused ? 'Resume_AI' : 'Pause_AI'}
              </button>
              <button
                disabled={busy}
                onClick={onFire}
                className="text-[10px] mono px-3 py-1.5 rounded-sm border border-rose-500/40 text-rose-400 hover:bg-rose-500/10 uppercase tracking-wider transition-all flex items-center gap-2 disabled:opacity-50">
                <i className="fas fa-bolt text-[10px]" />
                Fire_Genome
              </button>
            </div>
          )}
        </div>

        {/* Fitness curve */}
        <div className="text-[9px] mono text-gray-500 uppercase tracking-widest mb-2">Adversarial fitness · last {status.history?.length || 0} generations</div>
        <div className="bg-s-void rounded-lg p-3 border border-s-border" style={{ height: 100 }}>
          <svg viewBox="0 0 240 80" className="w-full h-full">
            {(status.history || []).map((h, i, arr) => {
              const x = (i / Math.max(1, arr.length - 1)) * 240;
              const y = 80 - (h.bestFitness / histMax) * 70 - 5;
              const next = arr[i + 1];
              if (!next) return null;
              const x2 = ((i + 1) / Math.max(1, arr.length - 1)) * 240;
              const y2 = 80 - (next.bestFitness / histMax) * 70 - 5;
              return <line key={i} x1={x} y1={y} x2={x2} y2={y2} stroke="#ef4444" strokeWidth="1.5" />;
            })}
            {(status.history || []).map((h, i, arr) => {
              const x = (i / Math.max(1, arr.length - 1)) * 240;
              const y = 80 - (h.meanFitness / histMax) * 70 - 5;
              return <circle key={`m-${i}`} cx={x} cy={y} r="1.5" fill="#d97706" />;
            })}
          </svg>
        </div>
        <div className="flex gap-4 text-[9px] mono text-gray-500 mt-2">
          <span><span className="inline-block w-3 h-0.5 bg-rose-500 mr-1 align-middle" />best fitness</span>
          <span><span className="inline-block w-1.5 h-1.5 rounded-full bg-amber-600 mr-1 align-middle" />mean fitness</span>
        </div>
      </div>

      {/* Population grid */}
      <div className="panel p-5">
        <div className="text-[10px] mono text-s-accent tracking-widest uppercase mb-4">Live population · {status.population?.length || 0} genomes in flight</div>
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-3">
          {(status.population || []).map(g => (
            <motion.div
              key={g.id}
              layout
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              className="rounded-lg p-3 border bg-s-void"
              style={{ borderColor: FAMILY_COLOR[g.family] || '#27272a' }}>
              <div className="flex items-start justify-between mb-2">
                <div>
                  <div className="text-[10px] mono uppercase tracking-wider" style={{ color: FAMILY_COLOR[g.family] || '#a1a1aa' }}>{g.family}</div>
                  <div className="text-[9px] mono text-gray-600">gen-{g.gen} · #{g.id}{g.parents?.length ? ` ← ${g.parents.join(',')}` : ''}</div>
                </div>
                <span className={`badge badge-${g.severity}`}>{g.severity}</span>
              </div>
              <div className="grid grid-cols-2 gap-1 text-[9px] mono text-gray-500">
                <div>band: <span className="text-gray-300">{g.freq_band}</span></div>
                <div>prop: <span className="text-gray-300">{g.propagation}</span></div>
                <div>evade: <span className="text-gray-300">{g.evasion}</span></div>
                <div>decoys: <span className="text-gray-300">{g.decoys}</span></div>
                <div>H: <span className="text-gray-300">{g.entropy}</span></div>
                <div>dBm: <span className="text-gray-300">{g.power_dbm}</span></div>
              </div>
              {g.target && (
                <div className="text-[9px] mono text-gray-500 mt-2 pt-2 border-t border-s-border/40">
                  → <span className="text-rose-400">{g.target.callsign || g.target.icao24}</span>
                  {g.fitness > 0 && <span className="ml-2">fitness: <span className="text-amber-400">{g.fitness}</span></span>}
                </div>
              )}
            </motion.div>
          ))}
        </div>
      </div>

      {status.fittest && (
        <div className="panel p-4 border" style={{ borderColor: '#7f1d1d' }}>
          <div className="text-[9px] mono text-rose-400 tracking-widest uppercase mb-1">Apex predator · gen {status.fittest.gen}</div>
          <div className="text-xs text-gray-200">{status.fittest.description || `${status.fittest.family} via ${status.fittest.freq_band}`}</div>
          <div className="text-[10px] mono text-gray-500 mt-1">fitness {status.fittest.fitness} · evasion {status.fittest.evasion}</div>
        </div>
      )}
    </div>
  );
};

// ========== 8c. DEFENSE CONSOLE ==========
// Live feed of every mitigation the auto-defender just executed. Runs on the
// dashboard so the operator (and the investor) can read off the outcome of
// every attack: which playbook fired, which target was blocked, and how
// confident the defender was.
const DefenseConsole = ({ stats, log }) => {
  const totals = stats?.totals || {};
  const recent = log?.length ? log : (stats?.recent || []);
  return (
    <div className="panel p-5 mb-4">
      <div className="flex items-start justify-between mb-4">
        <div>
          <div className="text-[10px] mono text-emerald-400 tracking-widest uppercase">Defense Console · auto-mitigation</div>
          <div className="font-display font-bold text-lg text-gradient mt-0.5">Active blue-team telemetry</div>
        </div>
        <div className="grid grid-cols-3 gap-3 text-center">
          <div className="px-3 py-1.5 rounded-sm bg-emerald-500/5 border border-emerald-500/30">
            <div className="text-[9px] mono text-emerald-400 uppercase tracking-widest">Blocked</div>
            <div className="text-lg font-display font-bold text-emerald-300">{totals.mitigated || 0}</div>
          </div>
          <div className="px-3 py-1.5 rounded-sm bg-rose-500/5 border border-rose-500/30">
            <div className="text-[9px] mono text-rose-400 uppercase tracking-widest">IPs cut</div>
            <div className="text-lg font-display font-bold text-rose-300">{totals.blockedIps || 0}</div>
          </div>
          <div className="px-3 py-1.5 rounded-sm bg-amber-500/5 border border-amber-500/30">
            <div className="text-[9px] mono text-amber-400 uppercase tracking-widest">Quarantined</div>
            <div className="text-lg font-display font-bold text-amber-300">{totals.quarantined || 0}</div>
          </div>
        </div>
      </div>
      {recent.length === 0 ? (
        <div className="text-[11px] mono text-gray-600 text-center py-4">no attacks yet — fire one to watch the defender respond</div>
      ) : (
        <div className="space-y-1 max-h-56 overflow-y-auto">
          {recent.slice(0, 12).map((e, i) => (
            <motion.div key={`${e.threatId || e.ts}-${i}`}
              layout
              initial={{ opacity: 0, x: -12 }}
              animate={{ opacity: 1, x: 0 }}
              className="flex items-center gap-3 text-[11px] mono px-2 py-1 rounded bg-emerald-500/3 border-l-2 border-emerald-500/50">
              <i className="fas fa-shield-halved text-emerald-400 text-[10px]" />
              <span className="text-emerald-300 font-bold tracking-wider">BLOCKED</span>
              <span className="text-gray-300">{e.threat_type}</span>
              <span className="text-gray-500">·</span>
              <span className="text-emerald-400">{e.action}</span>
              {e.target && (
                <>
                  <span className="text-gray-500">·</span>
                  <span className="text-gray-400">{e.target.kind}: <span className="text-gray-200">{String(e.target.value).slice(0, 32)}</span></span>
                </>
              )}
              <span className="ml-auto text-gray-600 text-[10px]">{new Date(e.ts).toLocaleTimeString()}</span>
            </motion.div>
          ))}
        </div>
      )}
    </div>
  );
};

// ========== 9. ALERTS PAGE ==========
const AlertsPage = ({ alerts, onAck }) => (
  <div className="panel p-5">
    <h2 className="text-[10px] mono text-s-accent tracking-widest uppercase mb-5">Alerts</h2>
    <div className="space-y-3">
      {(alerts || []).map(a => (
        <motion.div key={a.id} layout className="flex items-start gap-3 p-4 rounded-xl"
          style={{ background: a.acknowledged ? '#101012' : `${SEV[a.severity] || '#d97706'}08`, border: `1px solid ${a.acknowledged ? '#27272a' : (SEV[a.severity] || '#d97706') + '33'}` }}>
          <div className="w-1.5 h-1.5 rounded-full mt-1.5 flex-shrink-0" style={{ background: a.acknowledged ? '#374151' : SEV[a.severity] || '#d97706' }} />
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1">
              <SevBadge s={a.severity} />
              {a.aircraft_name && <span className="text-[10px] mono text-gray-600">{a.aircraft_name}</span>}
            </div>
            <div className="text-sm text-gray-200 font-medium">{a.title}</div>
            {a.message && <div className="text-xs text-gray-500 mt-1">{a.message}</div>}
            <div className="text-[10px] mono text-gray-700 mt-1">
              {new Date(a.detected_at).toLocaleString()}
              {a.acknowledged && a.ack_by_name && ` · Acked by ${a.ack_by_name}`}
            </div>
          </div>
          {!a.acknowledged && (
            <button onClick={() => onAck(a.id)} className="text-[10px] mono px-3 py-1.5 rounded-sm flex-shrink-0 transition-all bg-[#d9770615] border border-[#d9770640] text-[#d97706] hover:bg-[#d9770630] uppercase">
              ACK_LOG
            </button>
          )}
        </motion.div>
      ))}
    </div>
  </div>
);

// ========== 10. REPORTS PAGE ==========
const ReportsPage = ({ reports }) => {
  const [sel, setSel] = useState(null);
  return (
    <div className="space-y-4">
      <div className="panel p-5">
        <h2 className="text-[10px] mono text-s-accent tracking-widest uppercase mb-5">Attack Reports</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-s-border text-gray-600 mono">
                {['Date', 'Attack Type', 'Severity', 'Aircraft', 'ICAO24', 'Location', 'Score', 'Status'].map(h => <th key={h} className="text-left pb-2 pr-4 font-normal">{h}</th>)}
              </tr>
            </thead>
            <tbody className="divide-y divide-s-border/20">
              {(reports || []).map(r => (
                <tr key={r.threat_id} onClick={() => setSel(r)} className="hover:bg-s-border/10 cursor-pointer transition-colors">
                  <td className="py-2.5 pr-4 mono text-gray-600">{new Date(r.detected_at).toLocaleDateString()}</td>
                  <td className="py-2.5 pr-4 text-gray-300">{r.threat_type}</td>
                  <td className="py-2.5 pr-4"><SevBadge s={r.severity} /></td>
                  <td className="py-2.5 pr-4 text-gray-400">{r.aircraft_name || '–'}</td>
                  <td className="py-2.5 pr-4 mono text-gray-600">{r.icao24 || '–'}</td>
                  <td className="py-2.5 pr-4 text-gray-500">{r.location || '–'}</td>
                  <td className="py-2.5 pr-4 mono" style={{ color: r.score > 0.8 ? '#b91c1c' : '#f59e0b' }}>{parseFloat(r.score || 0).toFixed(3)}</td>
                  <td className="py-2.5"><span className={`badge badge-${r.threat_status === 'active' ? 'critical' : 'info'}`}>{r.threat_status}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
      <AnimatePresence>
        {sel && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/80 z-50 flex items-center justify-center p-4" onClick={() => setSel(null)}>
            <motion.div initial={{ scale: .95, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} exit={{ scale: .95, opacity: 0 }}
              className="panel p-7 w-full max-w-2xl" onClick={e => e.stopPropagation()}>
              <div className="flex justify-between mb-6">
                <div>
                  <h3 className="font-display font-bold text-2xl text-gradient">{sel.threat_type}</h3>
                  <div className="mono text-xs text-gray-500 mt-1">{new Date(sel.detected_at).toLocaleString()}</div>
                </div>
                <button onClick={() => setSel(null)} className="text-gray-500 hover:text-white text-xl"><i className="fas fa-xmark" /></button>
              </div>
              <div className="grid grid-cols-2 gap-4 text-xs mb-5">
                {[
                  ['Severity', <SevBadge s={sel.severity} />],
                  ['Aircraft', sel.aircraft_name || '–'],
                  ['ICAO24', sel.icao24 || '–'],
                  ['Callsign', sel.callsign || '–'],
                  ['Registration', sel.registration || '–'],
                  ['Location', sel.location || '–'],
                  ['Altitude', `${sel.altitude_ft?.toLocaleString() || '–'} ft`],
                  ['Speed', `${sel.speed_kts || '–'} kts`],
                  ['Threat Level', <span className={`badge badge-${sel.current_threat_level}`}>{sel.current_threat_level}</span>],
                  ['Protected', sel.is_protected ? '✓ Yes' : '✗ No'],
                  ['MITRE', sel.mitre_technique || '–'],
                  ['Score', <span style={{ color: '#ef4444' }}>{parseFloat(sel.score || 0).toFixed(4)}</span>],
                ].map(([l, v], i) => (
                  <div key={i} className="rounded-xl p-3" style={{ background: '#101012', border: '1px solid #27272a' }}>
                    <div className="mono text-[10px] text-gray-600 uppercase tracking-wider mb-1">{l}</div>
                    <div className="text-gray-200">{v}</div>
                  </div>
                ))}
              </div>
              {sel.description && (
                <div className="rounded-xl p-4" style={{ background: '#101012', border: '1px solid #27272a' }}>
                  <div className="mono text-[10px] text-gray-600 uppercase tracking-wider mb-2">Description</div>
                  <p className="text-sm text-gray-300 leading-relaxed">{sel.description}</p>
                </div>
              )}
              <button className="mt-5 w-full py-2.5 rounded-xl text-sm transition-all" style={{ background: 'rgba(217,119,6,0.08)', border: '1px solid rgba(217,119,6,0.3)', color: '#d97706' }} onClick={() => alert('PDF export coming soon')}>
                <i className="fas fa-file-pdf mr-2" />Export PDF Report
              </button>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

// ========== 11. AUDIT PAGE ==========
const AuditPage = ({ auditLog }) => (
  <div className="panel p-5">
    <h2 className="text-[10px] mono text-s-accent tracking-widest uppercase mb-5">Audit Log</h2>
    <table className="w-full text-xs">
      <thead>
        <tr className="border-b border-s-border text-gray-600 mono">
          {['Time', 'Action', 'Resource', 'Details'].map(h => <th key={h} className="text-left pb-2 pr-4 font-normal">{h}</th>)}
        </tr>
      </thead>
      <tbody className="divide-y divide-s-border/20">
        {(auditLog || []).map((l, i) => (
          <tr key={i}>
            <td className="py-2.5 pr-4 mono text-gray-600">{new Date(l.created_at).toLocaleTimeString()}</td>
            <td className="py-2.5 pr-4 text-gray-300">{l.action}</td>
            <td className="py-2.5 pr-4 mono text-gray-500">{l.resource || '–'}</td>
            <td className="py-2.5 text-gray-600 text-[10px] mono max-w-xs truncate">{JSON.stringify(l.details)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  </div>
);

// ========== 12. LIVE MAP (2D) ==========
// Rotatable plane marker — SVG rotates to match the aircraft heading.
const planeIcon = (level, heading) => {
  const c = SEV[level] || '#d97706';
  const pulse = level === 'under_attack' || level === 'critical';
  return L.divIcon({
    className: 'plane-marker',
    html: `
      <div style="transform:rotate(${heading || 0}deg);width:32px;height:32px;display:flex;align-items:center;justify-content:center;
        filter: drop-shadow(0 0 6px ${c});${pulse ? 'animation:pulse 1.2s infinite;' : ''}">
        <svg viewBox="0 0 24 24" width="28" height="28" fill="${c}" stroke="${c}" stroke-width="0.5">
          <path d="M21 16v-2l-8-5V3.5c0-.83-.67-1.5-1.5-1.5S10 2.67 10 3.5V9l-8 5v2l8-2.5V19l-2 1.5V22l3.5-1 3.5 1v-1.5L13 19v-5.5l8 2.5z"/>
        </svg>
      </div>`,
    iconSize: [32, 32], iconAnchor: [16, 16],
  });
};

const airportIcon = () => L.divIcon({
  className: 'airport-marker',
  html: `<div style="width:10px;height:10px;border-radius:50%;background:#52525b;border:2px solid #fff;
    box-shadow:0 0 8px #52525baa"></div>`,
  iconSize: [10, 10], iconAnchor: [5, 5],
});

const FitToPlanes = ({ positions }) => {
  const map = useMap();
  const fitted = useRef(false);
  useEffect(() => {
    if (fitted.current || !positions.length) return;
    const bounds = L.latLngBounds(positions);
    if (bounds.isValid()) map.fitBounds(bounds.pad(0.2));
    fitted.current = true;
  }, [positions, map]);
  return null;
};

const FlightControlPanel = ({ flight, airports, onClose, onPause, onReroute, onAttack }) => {
  const [to, setTo] = useState('');
  const [from, setFrom] = useState('');
  if (!flight) return null;
  const codes = Object.keys(airports || {});
  return (
    <div className="absolute bottom-4 right-4 z-[1000] panel p-4" style={{ width: 300 }}>
      <div className="flex items-center justify-between mb-3">
        <div>
          <div className="font-display font-bold text-sm text-s-accent">{flight.callsign || flight.icao24}</div>
          <div className="text-[10px] mono text-gray-500">{flight.icao24} · {flight.from}→{flight.to}</div>
        </div>
        <button onClick={onClose} className="text-gray-500 hover:text-white text-xs"><i className="fas fa-xmark" /></button>
      </div>
      <div className="grid grid-cols-3 gap-2 mb-3 text-[10px] mono text-gray-400">
        <div><div className="text-gray-600 text-[9px] uppercase">ALT</div>{flight.altitude_ft?.toLocaleString()}ft</div>
        <div><div className="text-gray-600 text-[9px] uppercase">SPD</div>{flight.speed_kts}kt</div>
        <div><div className="text-gray-600 text-[9px] uppercase">HDG</div>{flight.heading}°</div>
      </div>
      <div className="space-y-2">
        <div className="flex gap-2">
          <button onClick={() => onPause(flight, true)} className="flex-1 text-[10px] py-1.5 rounded border border-s-border hover:border-s-warn/60 text-s-warn"><i className="fas fa-pause mr-1" />Pause</button>
          <button onClick={() => onPause(flight, false)} className="flex-1 text-[10px] py-1.5 rounded border border-s-border hover:border-s-ok/60 text-s-ok"><i className="fas fa-play mr-1" />Resume</button>
        </div>
        <div className="flex gap-2">
          <select value={from} onChange={e => setFrom(e.target.value)} className="flex-1 text-[10px] bg-s-void border border-s-border rounded px-1.5 py-1 text-gray-300">
            <option value="">From…</option>{codes.map(c => <option key={c} value={c}>{c}</option>)}
          </select>
          <select value={to} onChange={e => setTo(e.target.value)} className="flex-1 text-[10px] bg-s-void border border-s-border rounded px-1.5 py-1 text-gray-300">
            <option value="">To…</option>{codes.map(c => <option key={c} value={c}>{c}</option>)}
          </select>
          <button onClick={() => from && to && onReroute(flight, from, to)} className="text-[10px] px-2 rounded border border-s-border hover:border-s-accent/60 text-s-accent"><i className="fas fa-route" /></button>
        </div>
        <button onClick={() => onAttack(flight)} className="w-full text-[10px] py-1.5 rounded border border-s-danger/40 bg-s-danger/10 text-s-danger hover:bg-s-danger/20"><i className="fas fa-bolt mr-1" />Simulate Attack</button>
      </div>
    </div>
  );
};

const LiveMap = ({ assets, forecast }) => {
  const [airports, setAirports] = useState({});
  const [flights, setFlights]   = useState([]);
  const [selected, setSelected] = useState(null);

  useEffect(() => {
    api.getAirports().then(r => setAirports(r.data || {})).catch(() => {});
    const refresh = () => api.getFlights().then(r => setFlights(r.data || [])).catch(() => {});
    refresh();
    const t = setInterval(refresh, 5000);
    return () => clearInterval(t);
  }, []);

  const ac = (assets || []).filter(a => a.asset_type === 'aircraft' && a.latitude && a.longitude);
  const positions = ac.map(a => [a.latitude, a.longitude]);
  const flightById = useMemo(() => {
    const m = new Map();
    for (const f of flights) m.set(f.asset_id, f);
    return m;
  }, [flights]);

  const underAttackCount = ac.filter(a => a.threat_level === 'under_attack' || a.threat_level === 'critical').length;

  const onPause   = (f, paused) => api.pauseFlight(f.asset_id || f.id, paused);
  const onReroute = (f, from, to) => api.rerouteFlight(f.asset_id || f.id, from, to);
  const onAttack  = (f) => api.injectAttack(f.asset_id || f.id, { severity: 'critical', type: 'gps_spoofing' });

  const selectedAsset = ac.find(a => a.id === selected);
  const selectedSnap  = selectedAsset ? { ...(flightById.get(selectedAsset.id) || {}),
    asset_id: selectedAsset.id, callsign: selectedAsset.callsign, icao24: selectedAsset.icao24,
    altitude_ft: selectedAsset.altitude_ft, speed_kts: selectedAsset.speed_kts, heading: selectedAsset.heading,
  } : null;

  return (
    <div className="panel relative" style={{ height: 'calc(100vh - 120px)' }}>
      <div className="absolute top-4 left-4 z-[1000] panel px-3 py-2 flex items-center gap-4">
        <div><span className="text-[10px] mono text-s-accent tracking-widest uppercase">Live Radar</span>
             <span className="ml-3 text-[10px] mono text-gray-600">{ac.length} aircraft</span></div>
        {underAttackCount > 0 && (
          <div className="text-[10px] mono px-2 py-1 rounded" style={{ background: '#b91c1c22', border: '1px solid #b91c1c66', color: '#ef4444' }}>
            <i className="fas fa-triangle-exclamation mr-1" />{underAttackCount} UNDER ATTACK
          </div>
        )}
      </div>
      <MapContainer center={[32.0, 34.9]} zoom={6} style={{ height: '100%', borderRadius: 14, background: '#05070f' }}>
        <TileLayer
          attribution='&copy; CARTO'
          url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
        />
        <FitToPlanes positions={positions} />

        {/* Airports */}
        {Object.entries(airports).map(([code, ap]) => (
          <Marker key={code} position={[ap.lat, ap.lon]} icon={airportIcon()}>
            <Popup>
              <div style={{ fontFamily: 'Syne,sans-serif', fontWeight: 700, color: '#fff' }}>{ap.name}</div>
              <div style={{ fontFamily: 'Share Tech Mono', fontSize: 11, color: '#9ca3af' }}>{code} · elev {ap.elev}ft</div>
            </Popup>
          </Marker>
        ))}

        {/* Flight paths: from origin → current → destination */}
        {ac.map(a => {
          const f = flightById.get(a.id);
          if (!f || !airports[f.from] || !airports[f.to]) return null;
          const origin = [airports[f.from].lat, airports[f.from].lon];
          const dest   = [airports[f.to].lat, airports[f.to].lon];
          const level  = a.threat_level;
          const color  = SEV[level] || '#d97706';
          return (
            <React.Fragment key={`path-${a.id}`}>
              <Polyline positions={[origin, [a.latitude, a.longitude]]}
                        pathOptions={{ color, weight: 2, opacity: 0.55 }} />
              <Polyline positions={[[a.latitude, a.longitude], dest]}
                        pathOptions={{ color, weight: 1, opacity: 0.25, dashArray: '4 6' }} />
            </React.Fragment>
          );
        })}

        {/* Attack halo under any under-attack/critical aircraft */}
        {ac.filter(a => a.threat_level === 'under_attack' || a.threat_level === 'critical').map(a => (
          <CircleMarker key={`halo-${a.id}`} center={[a.latitude, a.longitude]}
            radius={18} pathOptions={{ color: '#b91c1c', fillColor: '#b91c1c', fillOpacity: 0.2, weight: 1 }} />
        ))}

        {/* Pre-Crime: 60s ghost-trail projections per aircraft */}
        {forecast?.assets?.map(fa => fa.forecast && (
          <React.Fragment key={`fc-${fa.asset_id}`}>
            <Polyline positions={[[fa.lat, fa.lon], [fa.forecast.lat, fa.forecast.lon]]}
                      pathOptions={{ color: '#22d3ee', weight: 1.5, opacity: 0.6, dashArray: '2 4' }} />
            <CircleMarker center={[fa.forecast.lat, fa.forecast.lon]}
                          radius={4} pathOptions={{ color: '#22d3ee', fillColor: '#22d3ee', fillOpacity: 0.4, weight: 1 }}>
              <Popup>
                <div style={{ background: '#161618', border: '1px solid #22d3ee44', borderRadius: 8, padding: '6px 10px', color: '#fff' }}>
                  <div style={{ fontFamily: 'Share Tech Mono', fontSize: 10, color: '#22d3ee' }}>T+{forecast.horizon_s}s projection</div>
                  <div style={{ fontFamily: 'Share Tech Mono', fontSize: 11, color: '#a1a1aa' }}>{fa.callsign || fa.icao24}</div>
                </div>
              </Popup>
            </CircleMarker>
          </React.Fragment>
        ))}

        {/* Pre-Crime: hotspot heatmap cells */}
        {forecast?.cells?.filter(c => c.intensity > 0.15).map((c, i) => (
          <CircleMarker key={`heat-${i}`} center={[c.lat, c.lon]}
            radius={Math.max(6, c.intensity * 28)}
            pathOptions={{
              color: c.intensity > 0.6 ? '#dc2626' : '#f59e0b',
              fillColor: c.intensity > 0.6 ? '#dc2626' : '#f59e0b',
              fillOpacity: 0.08 + c.intensity * 0.18,
              weight: 0,
            }} />
        ))}

        {/* Pre-Crime: pulsing red ring on hot-zone hits (plane projected into high-intensity cell) */}
        {forecast?.hotZones?.map((h, i) => (
          <CircleMarker key={`hz-${i}`} center={[h.forecast.lat, h.forecast.lon]}
            radius={22} pathOptions={{ color: '#dc2626', fillColor: '#dc2626', fillOpacity: 0.0, weight: 2, dashArray: '4 4' }}>
            <Popup>
              <div style={{ background: '#161618', border: '1px solid #dc2626', borderRadius: 8, padding: '6px 10px', color: '#fff' }}>
                <div style={{ fontFamily: 'Share Tech Mono', fontSize: 10, color: '#dc2626' }}>PRE-CRIME · projected breach</div>
                <div style={{ fontFamily: 'Share Tech Mono', fontSize: 11, color: '#a1a1aa' }}>{h.callsign || h.icao24}</div>
                <div style={{ fontFamily: 'Share Tech Mono', fontSize: 10, color: '#a1a1aa' }}>likely type: {h.dominantType || 'unknown'}</div>
              </div>
            </Popup>
          </CircleMarker>
        ))}

        {/* Planes */}
        {ac.map(a => (
          <Marker key={a.id}
                  position={[a.latitude, a.longitude]}
                  icon={planeIcon(a.threat_level, a.heading)}
                  eventHandlers={{ click: () => setSelected(a.id) }}>
            <Popup className="shadow-popup">
              <div style={{ background: '#161618', border: '1px solid #27272a', borderRadius: 8, padding: '8px 12px', minWidth: 220, color: 'white' }}>
                <div style={{ fontFamily: 'Syne,sans-serif', fontWeight: 700, fontSize: 14, marginBottom: 4 }}>{a.name}</div>
                <div style={{ fontFamily: 'Share Tech Mono', fontSize: 11, color: '#9ca3af' }}>
                  <div>ICAO: {a.icao24} · {a.callsign}</div>
                  <div>{flightById.get(a.id)?.from || '?'} → {flightById.get(a.id)?.to || '?'}</div>
                  <div>Alt: {a.altitude_ft?.toLocaleString()}ft · {a.speed_kts}kt · {a.heading}°</div>
                  <div style={{ marginTop: 4 }}><span className={`badge badge-${a.threat_level}`}>{a.threat_level}</span></div>
                </div>
              </div>
            </Popup>
          </Marker>
        ))}
      </MapContainer>
      <FlightControlPanel flight={selectedSnap} airports={airports}
        onClose={() => setSelected(null)}
        onPause={onPause} onReroute={onReroute} onAttack={onAttack} />
    </div>
  );
};

// ========== 13. 3D GLOBE – live aircraft markers, scene built once ==========
// Splits concerns: the scene (earth, stars, lights, controls, anim loop) is
// built once on mount and torn down on unmount. Aircraft markers are synced
// from `assets` in a second effect so every 2-second position tick doesn't
// rebuild the whole GL context (which was leaking + freezing the tab).
const Globe3D = ({ assets, forecast }) => {
  const containerRef = useRef();
  const sceneRef = useRef(null);          // { scene, camera, renderer, controls, clouds }
  const markersRef = useRef(new Map());   // asset_id -> THREE.Group
  const forecastGroupRef = useRef(null);  // single THREE.Group holding all forecast viz
  const [error] = useState(false);

  const latLonToVector3 = (lat, lon, radius = 5.05) => {
    const phi = (90 - lat) * Math.PI / 180;
    const theta = lon * Math.PI / 180;
    return new THREE.Vector3(
      radius * Math.sin(phi) * Math.cos(theta),
      radius * Math.cos(phi),
      radius * Math.sin(phi) * Math.sin(theta),
    );
  };

  const buildAircraftMarker = (threatLevel) => {
    const color = SEV[threatLevel] || '#d97706';
    const group = new THREE.Group();
    const body = new THREE.Mesh(
      new THREE.BoxGeometry(0.14, 0.05, 0.32),
      new THREE.MeshStandardMaterial({ color, emissive: 0x000000, emissiveIntensity: 0.3 }),
    );
    group.add(body);
    const wings = new THREE.Mesh(
      new THREE.BoxGeometry(0.28, 0.02, 0.08),
      new THREE.MeshStandardMaterial({ color }),
    );
    wings.position.set(0, 0, -0.05);
    group.add(wings);
    const tail = new THREE.Mesh(
      new THREE.ConeGeometry(0.06, 0.1, 4),
      new THREE.MeshStandardMaterial({ color }),
    );
    tail.position.set(0, 0.04, -0.14);
    group.add(tail);
    if (threatLevel === 'under_attack' || threatLevel === 'critical') {
      const glow = new THREE.Mesh(
        new THREE.SphereGeometry(0.12, 8, 8),
        new THREE.MeshBasicMaterial({ color: 0xff3300, transparent: true, opacity: 0.4, blending: THREE.AdditiveBlending }),
      );
      glow.userData.isGlow = true;
      group.add(glow);
    }
    group.userData.threatLevel = threatLevel;
    return group;
  };

  // Build scene once.
  useEffect(() => {
    if (!containerRef.current) return;
    const container = containerRef.current;

    const scene = new THREE.Scene();
    scene.background = new THREE.Color(0x050b1a);
    scene.fog = new THREE.FogExp2(0x050b1a, 0.0008);

    const camera = new THREE.PerspectiveCamera(45, 1, 0.1, 1000);
    camera.position.set(0, 0, 13);

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: false });
    renderer.setSize(container.clientWidth, container.clientHeight);
    renderer.setPixelRatio(window.devicePixelRatio);
    container.appendChild(renderer.domElement);

    const controls = new OrbitControls(camera, renderer.domElement);
    controls.enableDamping = true;
    controls.dampingFactor = 0.05;
    controls.autoRotate = true;
    controls.autoRotateSpeed = 0.5;
    controls.enablePan = false;
    controls.zoomSpeed = 1.2;
    controls.rotateSpeed = 0.8;

    const textureLoader = new THREE.TextureLoader();
    const earthMaterial = new THREE.MeshPhongMaterial({
      map: textureLoader.load('https://threejs.org/examples/textures/planets/earth_atmos_2048.jpg'),
      bumpMap: textureLoader.load('https://threejs.org/examples/textures/planets/earth_normal_2048.jpg'),
      bumpScale: 0.05,
      specularMap: textureLoader.load('https://threejs.org/examples/textures/planets/earth_specular_2048.jpg'),
      specular: new THREE.Color('grey'),
      shininess: 5,
    });
    const earth = new THREE.Mesh(new THREE.SphereGeometry(5, 128, 128), earthMaterial);
    scene.add(earth);

    const cloudMaterial = new THREE.MeshPhongMaterial({
      map: textureLoader.load('https://threejs.org/examples/textures/planets/earth_clouds_1024.png'),
      transparent: true, opacity: 0.15, blending: THREE.AdditiveBlending,
    });
    const clouds = new THREE.Mesh(new THREE.SphereGeometry(5.02, 128, 128), cloudMaterial);
    scene.add(clouds);

    // Atmosphere halo.
    const atmos = new THREE.Mesh(
      new THREE.SphereGeometry(5.2, 64, 64),
      new THREE.MeshBasicMaterial({ color: 0x4a9eff, transparent: true, opacity: 0.08, side: THREE.BackSide }),
    );
    scene.add(atmos);

    // Stars
    const starGeo = new THREE.BufferGeometry();
    const starPos = new Float32Array(4000 * 3);
    for (let i = 0; i < 4000; i++) {
      const r = 400 + Math.random() * 100;
      const th = Math.random() * Math.PI * 2;
      const ph = Math.acos(2 * Math.random() - 1);
      starPos[i * 3]     = r * Math.sin(ph) * Math.cos(th);
      starPos[i * 3 + 1] = r * Math.sin(ph) * Math.sin(th);
      starPos[i * 3 + 2] = r * Math.cos(ph);
    }
    starGeo.setAttribute('position', new THREE.BufferAttribute(starPos, 3));
    scene.add(new THREE.Points(starGeo, new THREE.PointsMaterial({ color: 0xffffff, size: 0.35, transparent: true, opacity: 0.8 })));

    scene.add(new THREE.AmbientLight(0x404060));
    const mainLight = new THREE.DirectionalLight(0xffffff, 1.2);
    mainLight.position.set(10, 15, 5);
    scene.add(mainLight);
    const fillLight = new THREE.PointLight(0x4466cc, 0.5);
    fillLight.position.set(-5, 0, -8);
    scene.add(fillLight);

    let rafId;
    const animate = () => {
      controls.update();
      clouds.rotation.y += 0.0005;
      const t = Date.now();
      markersRef.current.forEach((m) => {
        const glow = m.children.find(c => c.userData?.isGlow);
        if (glow) glow.material.opacity = 0.25 + Math.sin(t * 0.006) * 0.2;
      });
      renderer.render(scene, camera);
      rafId = requestAnimationFrame(animate);
    };
    animate();

    const onResize = () => {
      if (!container) return;
      camera.aspect = container.clientWidth / container.clientHeight;
      camera.updateProjectionMatrix();
      renderer.setSize(container.clientWidth, container.clientHeight);
    };
    window.addEventListener('resize', onResize);
    onResize();

    sceneRef.current = { scene, camera, renderer, controls };

    // Persistent group for Pre-Crime visualization (ghost trails, heat dots, hot-zone rings)
    const forecastGroup = new THREE.Group();
    scene.add(forecastGroup);
    forecastGroupRef.current = forecastGroup;

    return () => {
      cancelAnimationFrame(rafId);
      window.removeEventListener('resize', onResize);
      controls.dispose();
      renderer.dispose();
      if (container && renderer.domElement.parentNode === container) {
        container.removeChild(renderer.domElement);
      }
      markersRef.current.clear();
      forecastGroupRef.current = null;
      sceneRef.current = null;
    };
  }, []);

  // Sync forecast overlay (ghost trails + heatmap dots + hot-zone rings) on the globe.
  useEffect(() => {
    const fg = forecastGroupRef.current;
    if (!fg) return;
    while (fg.children.length) {
      const c = fg.children[0];
      fg.remove(c);
      if (c.geometry) c.geometry.dispose();
      if (c.material) c.material.dispose();
    }
    if (!forecast) return;

    // Ghost trails: dashed line from current → projected position 60s out
    (forecast.assets || []).forEach(fa => {
      if (!fa.forecast) return;
      const a = latLonToVector3(fa.lat, fa.lon, 5.06);
      const b = latLonToVector3(fa.forecast.lat, fa.forecast.lon, 5.10);
      const geo = new THREE.BufferGeometry().setFromPoints([a, b]);
      const mat = new THREE.LineDashedMaterial({ color: 0x22d3ee, dashSize: 0.05, gapSize: 0.05, transparent: true, opacity: 0.65 });
      const line = new THREE.Line(geo, mat);
      line.computeLineDistances();
      fg.add(line);
      const dot = new THREE.Mesh(
        new THREE.SphereGeometry(0.04, 8, 8),
        new THREE.MeshBasicMaterial({ color: 0x22d3ee, transparent: true, opacity: 0.85 }),
      );
      dot.position.copy(b);
      fg.add(dot);
    });

    // Heatmap dots — small additive-blended pucks above the hot grid cells
    (forecast.cells || []).filter(c => c.intensity > 0.2).forEach(c => {
      const v = latLonToVector3(c.lat, c.lon, 5.04);
      const color = c.intensity > 0.6 ? 0xdc2626 : 0xf59e0b;
      const mat = new THREE.MeshBasicMaterial({ color, transparent: true, opacity: 0.18 + c.intensity * 0.4, blending: THREE.AdditiveBlending });
      const r = 0.05 + c.intensity * 0.18;
      const m = new THREE.Mesh(new THREE.SphereGeometry(r, 12, 12), mat);
      m.position.copy(v);
      fg.add(m);
    });

    // Hot-zone rings: pulsing red ring around projected breach points
    (forecast.hotZones || []).forEach(h => {
      const v = latLonToVector3(h.forecast.lat, h.forecast.lon, 5.12);
      const ring = new THREE.Mesh(
        new THREE.RingGeometry(0.18, 0.22, 32),
        new THREE.MeshBasicMaterial({ color: 0xdc2626, transparent: true, opacity: 0.85, side: THREE.DoubleSide }),
      );
      ring.position.copy(v);
      ring.lookAt(v.clone().multiplyScalar(2));
      fg.add(ring);
    });
  }, [forecast]);

  // Sync markers with assets whenever the list changes.
  useEffect(() => {
    const ref = sceneRef.current;
    if (!ref) return;
    const { scene } = ref;
    const live = new Map();
    (assets || [])
      .filter(a => a.asset_type === 'aircraft' && a.latitude != null && a.longitude != null)
      .forEach(a => live.set(a.id, a));

    // Remove stale markers.
    markersRef.current.forEach((marker, id) => {
      if (!live.has(id)) {
        scene.remove(marker);
        markersRef.current.delete(id);
      }
    });

    // Add or update.
    live.forEach((a) => {
      const pos = latLonToVector3(a.latitude, a.longitude);
      let marker = markersRef.current.get(a.id);
      if (!marker || marker.userData.threatLevel !== a.threat_level) {
        if (marker) scene.remove(marker);
        marker = buildAircraftMarker(a.threat_level);
        scene.add(marker);
        markersRef.current.set(a.id, marker);
      }
      marker.position.copy(pos);
      marker.lookAt(pos.clone().multiplyScalar(2));
    });
  }, [assets]);

  if (error) {
    return (
      <div className="panel flex items-center justify-center" style={{ height: 'calc(100vh - 120px)' }}>
        <div className="text-center text-gray-400">
          <i className="fas fa-globe-americas text-4xl mb-3 block" />
          <p className="text-sm">Unable to load 3D Globe.</p>
        </div>
      </div>
    );
  }

  return <div ref={containerRef} className="w-full rounded-2xl overflow-hidden panel" style={{ height: 'calc(100vh - 120px)' }} />;
};

// ========== 14. VOICE ALERT ==========
const useVoiceAlert = () => {
  const speak = useCallback((text) => {
    if ('speechSynthesis' in window) {
      const utterance = new SpeechSynthesisUtterance(text);
      utterance.lang = 'he-IL';
      utterance.rate = 0.9;
      window.speechSynthesis.cancel();
      window.speechSynthesis.speak(utterance);
    }
  }, []);
  return speak;
};

// ========== 15. KEYBOARD SHORTCUTS ==========
const useKeyboardShortcuts = (handlers) => {
  useEffect(() => {
    const listener = (e) => {
      const key = e.key.toLowerCase();
      if (handlers[key]) { handlers[key](); e.preventDefault(); }
    };
    window.addEventListener('keydown', listener);
    return () => window.removeEventListener('keydown', listener);
  }, [handlers]);
};

// ========== 16. NOTIFICATIONS ==========
const notify = (title, options) => {
  if (Notification.permission === 'granted') new Notification(title, options);
  else if (Notification.permission !== 'denied') Notification.requestPermission().then(perm => { if (perm === 'granted') new Notification(title, options); });
};

// ========== 17. PDF EXPORT ==========
const exportToPDF = (elementId, filename) => {
  const element = document.getElementById(elementId);
  if (!element) return;
  html2pdf().set({ margin: 0.5, filename: `${filename}.pdf`, image: { type: 'jpeg', quality: 0.98 }, html2canvas: { scale: 2 }, jsPDF: { unit: 'in', format: 'a4', orientation: 'portrait' } }).from(element).save();
};

// ========== 18. THEME ==========
const useTheme = () => {
  const [theme, setTheme] = useState(localStorage.getItem('shadowTheme') || 'dark');
  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('shadowTheme', theme);
  }, [theme]);
  return [theme, setTheme];
};

// ========== 19. LIVE TELEMETRY (WS-driven) ==========
// Merges real-time simulator `asset:position` events into the asset list and
// patches `asset:threat_level` transitions in place. No random jitter — if
// there's no backend event, the data stays put.
const useTelemetry = (initialAssets, on) => {
  const [assets, setAssets] = useState(initialAssets);
  useEffect(() => { setAssets(initialAssets); }, [initialAssets]);

  useEffect(() => {
    if (!on) return;
    const unsubPos = on('asset:position', (p) => {
      setAssets(prev => prev.map(a => (a.id === p.asset_id ? {
        ...a,
        latitude: p.lat,
        longitude: p.lon,
        altitude_ft: p.altitude_ft,
        heading: p.heading,
        speed_kts: p.speed_kts,
        last_contact: new Date().toISOString(),
        _route: { from: p.from, to: p.to, progress: p.progress },
      } : a)));
    });
    const unsubLvl = on('asset:threat_level', (p) => {
      setAssets(prev => prev.map(a => (a.id === p.asset_id
        ? { ...a, threat_level: p.threat_level } : a)));
    });
    return () => { unsubPos(); unsubLvl(); };
  }, [on]);

  return assets;
};

// ========== 20. COPILOT CHAT – ULTIMATE (Mistral 7B, קומפקטי, מהיר) ==========
// ========== 20. COPILOT CHAT – ULTIMATE (GPT-level, Multilingual, Smart) ==========
// ========== 20. COPILOT CHAT – ULTIMATE AI (Mistral 7B + RTL + Smart Actions) ==========


// ========== 21. LOGIN PAGE ==========
const LoginPage = () => {
  const { login } = useAuth();
  const [u, setU] = useState('elal_admin');
  const [p, setP] = useState('shadow123');
  const [err, setErr] = useState('');
  const [loading, setLoading] = useState(false);
  const DEMO = [
    { name: 'EL AL', u: 'elal_admin', role: 'admin', tenant_id: '11111111-1111-1111-1111-111111111111' },
    { name: 'Israir', u: 'israir_admin', role: 'admin', tenant_id: '22222222-2222-2222-2222-222222222222' },
    { name: 'Arkia', u: 'arkia_admin', role: 'admin', tenant_id: '33333333-3333-3333-3333-333333333333' },
  ];
  const submit = async (e) => {
    e.preventDefault(); setErr(''); setLoading(true);
    try { await login(u, p); } catch (e) { setErr(e?.error || 'Login failed'); }
    setLoading(false);
  };
  return (
    <div className="min-h-screen flex items-center justify-center px-4">
      <div className="w-full max-w-md">
        <div className="text-center mb-10">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl mb-4" style={{ background: 'linear-gradient(135deg,#d9770622,#52525b22)', border: '1px solid #d9770644' }}>
            <i className="fas fa-shield-halved text-2xl" style={{ color: '#d97706' }} />
          </div>
          <h1 className="font-display text-3xl font-bold text-gradient">SHADOW NDR</h1>
          <p className="text-xs mono text-gray-600 tracking-widest mt-1">MULTI-TENANT APEX v2.0</p>
        </div>
        <div className="panel p-8">
          <form onSubmit={submit} className="space-y-4">
            <div><label className="text-xs mono text-gray-500 uppercase tracking-widest block mb-1.5">Username</label><input value={u} onChange={e => setU(e.target.value)} className="w-full bg-s-void border border-s-border rounded-lg px-3 py-2.5 text-sm text-white outline-none focus:border-s-accent/60 transition-colors" /></div>
            <div><label className="text-xs mono text-gray-500 uppercase tracking-widest block mb-1.5">Password</label><input type="password" value={p} onChange={e => setP(e.target.value)} className="w-full bg-s-void border border-s-border rounded-lg px-3 py-2.5 text-sm text-white outline-none focus:border-s-accent/60 transition-colors" /></div>
            {err && <div className="text-xs text-s-danger mono">{err}</div>}
            <button type="submit" disabled={loading} className="w-full py-2.5 rounded-lg text-sm font-body font-medium transition-all" style={{ background: 'linear-gradient(135deg,#d9770620,#52525b20)', border: '1px solid #d9770644', color: '#d97706' }}>{loading ? 'Authenticating...' : 'Authenticate →'}</button>
          </form>
          <div className="mt-6 border-t border-s-border pt-5">
            <p className="text-[10px] mono text-gray-600 mb-3 uppercase tracking-widest">Demo tenants</p>
            <div className="grid grid-cols-3 gap-2">{DEMO.map(d => (<button key={d.name} onClick={() => { setU(d.u); setP('shadow123'); }} className="text-xs py-1.5 px-2 rounded-lg border border-s-border hover:border-s-accent/40 transition-colors text-gray-400 hover:text-s-accent">{d.name}</button>))}</div>
          </div>
        </div>
      </div>
    </div>
  );
};

// ========== 21.5. CRITICAL ATTACK BANNER ==========
// Prominent top banner surfaces in-flight attacks. Pulses red, lists the ICAO24
// codes under attack, and click jumps to the live map.
const CriticalBanner = ({ assets, onJumpToMap }) => {
  const under = useMemo(() => (assets || []).filter(a =>
    a.threat_level === 'under_attack' || a.threat_level === 'critical'), [assets]);
  if (!under.length) return null;
  const ids = under.map(a => a.icao24 || a.name).slice(0, 6).join(' · ');
  return (
    <motion.div
      initial={{ y: -40, opacity: 0 }} animate={{ y: 0, opacity: 1 }}
      className="relative overflow-hidden rounded-xl mb-4 cursor-pointer"
      onClick={onJumpToMap}
      style={{
        background: 'linear-gradient(90deg, rgba(185,28,28,0.2), rgba(185,28,28,0.08))',
        border: '1px solid rgba(185,28,28,0.55)',
        boxShadow: '0 0 24px rgba(185,28,28,0.25), inset 0 0 24px rgba(185,28,28,0.1)',
      }}>
      <div className="absolute inset-0 pointer-events-none"
        style={{ background: 'linear-gradient(90deg, transparent, rgba(185,28,28,0.35), transparent)',
                 animation: 'sweep 2.4s linear infinite' }} />
      <div className="relative flex items-center gap-3 px-4 py-2.5">
        <motion.i className="fas fa-triangle-exclamation"
          animate={{ opacity: [1, 0.3, 1] }} transition={{ duration: 1, repeat: Infinity }}
          style={{ color: '#ef4444', fontSize: 18 }} />
        <div className="flex-1 min-w-0">
          <div className="font-display font-bold text-sm text-white tracking-wide">
            {under.length} AIRCRAFT UNDER ATTACK
          </div>
          <div className="mono text-[10px] text-gray-300 truncate">{ids}</div>
        </div>
        <span className="mono text-[10px] text-s-danger opacity-80">VIEW LIVE MAP →</span>
      </div>
    </motion.div>
  );
};

// ========== 22. MAIN APP ==========
const Main = () => {
  const { user, logout } = useAuth();
  const { status: wsStatus, events, on: wsOn } = useWebSocket();
  const speak = useVoiceAlert();
  const [theme, setTheme] = useTheme();
  const [page, setPage] = useState('dashboard');
  const [dashData, setDashData] = useState(null);
  const [assets, setAssets] = useState([]);
  const [threats, setThreats] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [reports, setReports] = useState([]);
  const [toasts, setToasts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [show3D, setShow3D] = useState(false);
  const [filteredAssets, setFilteredAssets] = useState(null);
  const [selectedAsset, setSelectedAsset] = useState(null);
  

  const load = useCallback(async () => {
    setLoading(true);
    const results = await Promise.allSettled([
      api.getDashboard(),
      api.getAssets(),
      api.getThreats(),
      api.getAlerts(),
      api.getReports(),
    ]);
    const pick = (i) => results[i].status === 'fulfilled' ? results[i].value : null;
    const d = pick(0), a = pick(1), th = pick(2), al = pick(3), rp = pick(4);
    if (d?.data) setDashData(d.data);
    setAssets(a?.data || []);
    setThreats(th?.data || []);
    setAlerts(al?.data || []);
    setReports(rp?.data || []);
    results.forEach((r, i) => { if (r.status === 'rejected') console.warn(`load[${i}] failed:`, r.reason?.response?.data || r.reason?.message); });
    setLoading(false);
  }, []);
  useEffect(() => { load(); const t = setInterval(load, 30000); return () => clearInterval(t); }, [load]);
  const handleIsolateAsset = async (asset, isolating = true) => {
    try {
      const res = await api.isolateAsset(asset.id, isolating, isolating ? 'manual quarantine via UI' : 'manual restore via UI');
      const updated = res?.data || asset;
      setAssets(prev => prev.map(a => a.id === updated.id ? { ...a, ...updated } : a));
      const toastId = `isolate-${asset.id}-${Date.now()}`;
      setToasts(prev => [{
        id: toastId,
        state: 'info',
        severity: 'info',
        message: `${asset.icao24 || asset.name} ${isolating ? 'isolated' : 'restored'}`,
        sub: isolating ? 'asset quarantined and reported' : 'asset returned to active service',
        ts: Date.now(),
      }, ...prev].slice(0, 6));
      setTimeout(() => setToasts(p => p.filter(t => t.id !== toastId)), 6000);
      return updated;
    } catch (err) {
      const msg = err?.error || err?.message || 'action failed';
      setToasts(prev => [{
        id: `isolate-err-${Date.now()}`,
        state: 'info',
        severity: 'high',
        message: `failed to ${isolating ? 'isolate' : 'restore'} ${asset.icao24 || asset.name}`,
        sub: msg,
        ts: Date.now(),
      }, ...prev].slice(0, 6));
      throw err;
    }
  };

  const handleDemoBreach = async () => {
    try {
      const list = await api.getFlights();
      const flights = list?.data || [];
      if (flights.length === 0) {
        setToasts(prev => [{
          id: `demo-empty-${Date.now()}`, state: 'info', severity: 'info',
          message: 'no live flights to attack', sub: 'start the simulator first', ts: Date.now(),
        }, ...prev].slice(0, 6));
        return;
      }
      const target = flights[Math.floor(Math.random() * flights.length)];
      const types = ['gps_spoofing', 'ads-b_injection', 'mode-s_replay', 'rogue_atc'];
      await api.injectAttack(target.assetId, {
        severity: 'critical',
        type: types[Math.floor(Math.random() * types.length)],
      });
    } catch (err) {
      console.error('Demo breach failed:', err);
    }
  };

  const liveAssets = useTelemetry(assets, wsOn);
  const displayAssets = filteredAssets ?? liveAssets;

  // State-aware incident toast deck. A `threat:new` pushes a sticky toast
  // keyed by threat id; the matching `threat:resolved` flips its state to
  // 'resolved' (green ✓) and schedules a 3.5s fade. Manual ack dismisses.
  const [history, setHistory] = useState([]);
  const [unread, setUnread] = useState(0);
  const [bellOpen, setBellOpen] = useState(false);
  const [defenseLog, setDefenseLog] = useState([]);
  const [defenderStats, setDefenderStats] = useState(null);
  const resolveTimers = useRef(new Map());

  // Pull initial defender stats so the panel shows totals on first paint.
  useEffect(() => {
    api.getDefenderStatus().then(r => setDefenderStats(r.data)).catch(() => {});
    const t = setInterval(() => api.getDefenderStatus().then(r => setDefenderStats(r.data)).catch(() => {}), 15000);
    return () => clearInterval(t);
  }, []);

  // ── SEART (generative red-team) state ────────────────────────────────────
  const [seartStatus, setSeartStatus] = useState(null);
  const [seartBusy, setSeartBusy] = useState(false);
  useEffect(() => {
    let alive = true;
    api.getRedTeamStatus().then(r => { if (alive) setSeartStatus(r.data); }).catch(() => {});
    if (!wsOn) return () => { alive = false; };
    const unsub = wsOn('seart:generation', (snap) => {
      setSeartStatus(prev => ({
        ...(prev || {}),
        running: true,
        generation: snap.generation,
        popSize: snap.population?.length ?? prev?.popSize ?? 0,
        history: snap.history,
        population: snap.population,
        totalFired: snap.totalFired,
        totalSlipped: snap.totalSlipped,
        fittest: prev?.fittest,
      }));
    });
    return () => { alive = false; unsub && unsub(); };
  }, [wsOn]);
  const handleSeartPause = async (paused) => {
    setSeartBusy(true);
    try { const r = await api.pauseRedTeam(paused); setSeartStatus(r.data); }
    finally { setSeartBusy(false); }
  };
  const handleSeartFire = async () => {
    setSeartBusy(true);
    try { await api.fireRedTeamNow(); }
    catch (err) {
      const msg = err?.error || 'no live targets';
      setToasts(prev => [{ id: `seart-${Date.now()}`, state: 'info', severity: 'high', message: 'red-team fire failed', sub: msg, ts: Date.now() }, ...prev].slice(0, 6));
    }
    finally { setSeartBusy(false); }
  };

  // ── Pre-Crime forecast state ─────────────────────────────────────────────
  const [forecast, setForecast] = useState(null);
  useEffect(() => {
    let alive = true;
    api.getForecast().then(r => { if (alive) setForecast(r.data); }).catch(() => {});
    if (!wsOn) return () => { alive = false; };
    const unsub = wsOn('forecast:tick', (snap) => { if (alive) setForecast(snap); });
    return () => { alive = false; unsub && unsub(); };
  }, [wsOn]);

  useEffect(() => {
    if (!wsOn) return;

    const labelFor = (t) => `${t?.threat_type || 'threat'}${t?.icao24 ? ` · ${t.icao24}` : ''}`;
    const subFor = (t) => t?.description ? t.description.slice(0, 90) : (t?.source_ip ? `from ${t.source_ip}` : null);

    const onNew = (t) => {
      const tid = t?.id ?? `live-${Date.now()}`;
      const sev = t?.severity || 'high';
      const id = `threat-${tid}`;
      const entry = {
        id, threatId: tid, state: 'active', severity: sev,
        message: labelFor(t), sub: subFor(t), threat: t, ts: Date.now(),
      };
      setToasts(prev => {
        const without = prev.filter(p => p.id !== id);
        return [entry, ...without].slice(0, 6);
      });
      setHistory(prev => [entry, ...prev.filter(p => p.id !== id)].slice(0, 50));
      setUnread(u => u + 1);
      if (sev === 'emergency' || sev === 'critical') {
        speak(`${sev}: ${t.threat_type} on ${t.icao24 || 'aircraft'}`);
        notify('Shadow NDR — Active breach', {
          body: `${t.threat_type}${t.icao24 ? ` on ${t.icao24}` : ''}${t.description ? ' — ' + t.description.slice(0, 80) : ''}`,
          icon: '/favicon.ico',
        });
      }
      load();
    };

    const onResolved = (t) => {
      const tid = t?.id;
      if (tid == null) return load();
      const id = `threat-${tid}`;
      setToasts(prev => prev.map(p => p.id === id ? { ...p, state: 'resolved', ts: Date.now() } : p));
      setHistory(prev => prev.map(p => p.id === id ? { ...p, state: 'resolved', ts: Date.now() } : p));
      const existing = resolveTimers.current.get(id);
      if (existing) clearTimeout(existing);
      const handle = setTimeout(() => {
        setToasts(prev => prev.filter(p => p.id !== id));
        resolveTimers.current.delete(id);
      }, 3500);
      resolveTimers.current.set(id, handle);
      load();
    };

    const onMitigated = (t) => {
      const tid = t?.id;
      if (tid == null) return load();
      const id = `threat-${tid}`;
      const mitigation = t?.mitigation || t?.raw_features?.mitigation || null;
      const subLine = mitigation
        ? `BLOCKED via ${mitigation.action}${mitigation.targets?.[0] ? ` · ${mitigation.targets[0].kind}: ${mitigation.targets[0].value}` : ''}`
        : 'attack neutralized';
      setToasts(prev => {
        const found = prev.find(p => p.id === id);
        if (found) {
          return prev.map(p => p.id === id
            ? { ...p, state: 'mitigated', sub: subLine, mitigation, ts: Date.now() }
            : p);
        }
        // No matching active toast (manual injection bypass) — synthesize a blocked toast
        return [{
          id, threatId: tid, state: 'mitigated', severity: t.severity || 'high',
          message: `${t.threat_type || 'threat'}${t.icao24 ? ` · ${t.icao24}` : ''}`,
          sub: subLine, mitigation, threat: t, ts: Date.now(),
        }, ...prev].slice(0, 6);
      });
      setHistory(prev => prev.map(p => p.id === id ? { ...p, state: 'mitigated', sub: subLine, mitigation, ts: Date.now() } : p));
      // Hold the green BLOCKED state on screen ~6s so the operator clearly sees it
      const existing = resolveTimers.current.get(id);
      if (existing) clearTimeout(existing);
      const handle = setTimeout(() => {
        setToasts(prev => prev.filter(p => p.id !== id));
        resolveTimers.current.delete(id);
      }, 6000);
      resolveTimers.current.set(id, handle);
      // Push a defense-log entry for the dashboard card
      setDefenseLog(prev => [{
        ts: Date.now(), threatId: tid, threat_type: t.threat_type,
        severity: t.severity, action: mitigation?.action, technique: mitigation?.technique,
        target: mitigation?.targets?.[0],
      }, ...prev].slice(0, 30));
      load();
    };

    const onAlert = (a) => {
      const id = `alert-${a?.id || Date.now()}`;
      const entry = {
        id, state: 'info', severity: a?.severity || 'high',
        message: a?.title || 'New alert', sub: a?.message ? a.message.slice(0, 100) : null,
        ts: Date.now(),
      };
      setToasts(prev => [entry, ...prev].slice(0, 6));
      setHistory(prev => [entry, ...prev].slice(0, 50));
      setUnread(u => u + 1);
      setTimeout(() => setToasts(prev => prev.filter(p => p.id !== id)), 6000);
    };

    const unsubNew = wsOn('threat:new', onNew);
    const unsubUpd = wsOn('threat:update', (t) => {
      // dedupe hit — refresh the existing sticky toast's sub-line so the
      // operator can see hit_count climb without spawning new toasts.
      const id = `threat-${t?.id}`;
      setToasts(prev => prev.map(p => p.id === id
        ? { ...p, sub: t.hit_count ? `× ${t.hit_count} hits · ${t.description?.slice(0, 60) || ''}` : p.sub, ts: Date.now() }
        : p));
    });
    const unsubRes = wsOn('threat:resolved', onResolved);
    const unsubMit = wsOn('threat:mitigated', onMitigated);
    const unsubAlert = wsOn('new_alert', onAlert);

    return () => {
      unsubNew(); unsubUpd(); unsubRes(); unsubMit(); unsubAlert();
      resolveTimers.current.forEach(h => clearTimeout(h));
      resolveTimers.current.clear();
    };
  }, [wsOn, speak, load]);

  // Active-incident derivation for the banner. Prefers the sticky-toast
  // set (which reflects live WS state) but falls back to the polled
  // threats list so the banner still surfaces on first paint.
  const activeIncidents = useMemo(() => {
    const live = toasts.filter(t => t.state === 'active' && t.threat).map(t => t.threat);
    if (live.length > 0) return live;
    return threats.filter(th => th?.status === 'active');
  }, [toasts, threats]);

  const unacked = useMemo(() => alerts.filter(a => !a.acknowledged).length, [alerts]);

  const handleNavigate = (target) => setPage(target);
  const handleFilterAssets = (filtered) => setFilteredAssets(filtered);
  const handleSelectAsset = (asset) => setSelectedAsset(asset);
  const handleAcknowledgeAlert = async (id) => { await api.ackAlert(id); load(); };
  const handleClearSelected = () => setSelectedAsset(null);

  useKeyboardShortcuts({
    '1': () => setPage('dashboard'), '2': () => setPage('map'), '3': () => setPage('assets'),
    '4': () => setPage('threats'), '5': () => setPage('alerts'), '6': () => setPage('reports'),
    '7': () => setPage('audit'), 'r': () => load(), 't': () => setTheme(theme === 'dark' ? 'neon' : 'dark'),
  });

  const handleExportPDF = () => exportToPDF('report-pdf-content', `shadow_ndr_report_${new Date().toISOString().slice(0, 19)}`);
  if (loading && !dashData) return <div className="flex items-center justify-center min-h-screen flex-col gap-4"><div className="w-10 h-10 rounded-full border-2 border-s-accent border-t-transparent animate-spin" /><div className="mono text-s-accent text-xs tracking-widest animate-pulse">LOADING SHADOW NDR...</div></div>;

  return (
    <div className="min-h-screen flex scanlines overflow-hidden" data-theme={theme}>
      <Sidebar page={page} setPage={setPage} user={user} logout={logout} unacked={unacked} />
      <IncidentToast toasts={toasts} onDismiss={id => {
        const h = resolveTimers.current.get(id);
        if (h) { clearTimeout(h); resolveTimers.current.delete(id); }
        setToasts(p => p.filter(t => t.id !== id));
      }} />
      <CopilotChat 
  onNavigate={handleNavigate} 
  onFilterAssets={handleFilterAssets} 
  onSelectAsset={handleSelectAsset} 
  onAcknowledgeAlert={handleAcknowledgeAlert}
  onIsolateAsset={handleIsolateAsset}
/>
      <main style={{ marginLeft: 220 }} className="flex-1 p-6 min-h-screen">
        <div className="flex items-center justify-between mb-6">
          <div><h1 className="font-display font-bold text-xl text-gradient">{NAV.find(n => n.id === page)?.label || page}</h1><div className="text-[10px] mono text-gray-600 mt-0.5">{user?.tenant_name} · {new Date().toLocaleTimeString()}</div></div>
          <div className="flex items-center gap-3">
            {(user?.role === 'admin' || user?.role === 'superadmin') && (
              <button
                onClick={handleDemoBreach}
                className="text-[10px] mono px-3 py-1.5 rounded-sm border border-[#b91c1c] text-[#ef4444] hover:bg-[#b91c1c20] uppercase tracking-wider transition-all flex items-center gap-2"
                title="Inject a critical attack on a random live flight">
                <i className="fas fa-radiation text-[10px]" />
                <span>Demo_Breach</span>
              </button>
            )}
            <NotificationBell
              history={history}
              unread={unread}
              isOpen={bellOpen}
              onOpen={() => { setBellOpen(o => !o); if (!bellOpen) setUnread(0); }}
              onClear={() => { setHistory([]); setUnread(0); }}
              onJump={() => { setBellOpen(false); setPage('threats'); }}
            />
            <button onClick={handleExportPDF} className="text-[10px] mono px-3 py-1.5 rounded-sm border border-[#27272a] text-[#71717a] hover:bg-[#1c1c20] hover:text-[#e4e4e7] uppercase transition-all flex items-center gap-2">
              <i className="fas fa-file-pdf text-[9px]" />
              <span>Export_PDF</span>
            </button>
            <button onClick={load} className="text-[10px] mono px-3 py-1.5 rounded-sm border border-[#27272a] text-[#71717a] hover:bg-[#1c1c20] hover:text-[#e4e4e7] uppercase transition-all flex items-center gap-2">
              <i className="fas fa-rotate-right text-[9px]" />
              <span>Sync_Data</span>
            </button>
            <div className={`flex items-center gap-2 px-3 py-1.5 rounded-sm bg-[#101012] border border-[#27272a] text-[9px] mono tracking-widest ${wsStatus === 'connected' ? 'text-[#10b981]' : wsStatus === 'reconnecting' ? 'text-[#d97706]' : 'text-[#ef4444]'}`}>
              <div className="w-1.5 h-1.5 rounded-full animate-pulse" style={{ background: wsStatus === 'connected' ? '#10b981' : wsStatus === 'reconnecting' ? '#d97706' : '#b91c1c' }} />
              {wsStatus.toUpperCase()}_LINK
            </div>
          </div>
        </div>
        <ActiveIncidentBanner activeThreats={activeIncidents} onJump={() => setPage('threats')} />
        <CriticalBanner assets={displayAssets} onJumpToMap={() => setPage('map')} />
        <AnimatePresence mode="wait">
          <motion.div key={page} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }} transition={{ duration: .2 }}>
            {page === 'dashboard' && <><DefenseConsole stats={defenderStats} log={defenseLog} /><Dashboard data={dashData} /><ForecastChart timeline={dashData?.timeline} /></>}
            {page === 'map' && (<div><div className="flex justify-end mb-2 gap-2"><button onClick={() => setShow3D(false)} className={`text-[10px] mono px-3 py-1 rounded-sm border ${!show3D ? 'border-[#d97706] text-[#d97706] bg-[#d9770610]' : 'border-[#27272a] text-[#52525b] hover:text-[#a1a1aa]'}`}>[ 2D_RADAR ]</button><button onClick={() => setShow3D(true)} className={`text-[10px] mono px-3 py-1 rounded-sm border ${show3D ? 'border-[#d97706] text-[#d97706] bg-[#d9770610]' : 'border-[#27272a] text-[#52525b] hover:text-[#a1a1aa]'}`}>[ 3D_GLOBE ]</button></div>{show3D ? <Globe3D assets={displayAssets} forecast={forecast} /> : <LiveMap assets={displayAssets} forecast={forecast} />}</div>)}
            {page === 'assets' && <AssetsPage assets={displayAssets} user={user} selectedAsset={selectedAsset} onClearSelected={handleClearSelected} onIsolate={(asset, isolating) => handleIsolateAsset(asset, isolating)} />}
            {page === 'threats' && <ThreatsPage threats={threats} onUpdateStatus={async (id, status) => { await api.updateThreat(id, { status }); load(); }} />}
            {page === 'redteam' && <SeartPage user={user} status={seartStatus} onPause={handleSeartPause} onFire={handleSeartFire} busy={seartBusy} />}
            {page === 'alerts' && <AlertsPage alerts={alerts} onAck={async (id) => { await api.ackAlert(id); load(); }} />}
            {page === 'reports' && <ReportsPage reports={reports} />}
            {page === 'audit' && <AuditPage auditLog={dashData?.auditLog} />}
          </motion.div>
        </AnimatePresence>
      </main>
    </div>
  );
};

// ========== 23. ROOT ==========
export default function App() {
  return (
    <AuthProvider>
      <AppInner />
    </AuthProvider>
  );
}
function AppInner() {
  const { user } = useAuth();
  return user ? <Main /> : <LoginPage />;
}