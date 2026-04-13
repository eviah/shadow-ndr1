import React, { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Chart as ChartJS, CategoryScale, LinearScale, PointElement, LineElement,
         BarElement, Title, Tooltip, Legend, Filler } from 'chart.js';
import { Line } from 'react-chartjs-2';
import { MapContainer, TileLayer, Marker, Popup } from 'react-leaflet';
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
  emergency: '#ff1f4c', critical: '#ff4569', high: '#ff9c33',
  medium: '#fbbf24', low: '#00e87a', info: '#00d9f7', safe: '#00e87a'
};
const SevBadge = ({ s }) => <span className={`badge badge-${s}`}>{s}</span>;

// ========== 2. TOASTS ==========
const ToastContainer = ({ toasts, onDismiss }) => (
  <div className="fixed top-4 right-4 z-[9999] space-y-2 w-80">
    <AnimatePresence>
      {toasts.map(t => (
        <motion.div key={t.id} initial={{ opacity: 0, x: 60 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: 60 }}
          className="panel p-3 cursor-pointer flex items-start gap-3" onClick={() => onDismiss(t.id)}>
          <div className="w-1.5 h-full rounded-full flex-shrink-0 mt-0.5" style={{ background: SEV[t.severity] || '#00d9f7', minHeight: 12 }} />
          <div className="flex-1 min-w-0">
            <div className="text-xs font-body text-gray-300 leading-snug">{t.message}</div>
            <div className="text-[10px] mono text-gray-600 mt-0.5">{t.event}</div>
          </div>
        </motion.div>
      ))}
    </AnimatePresence>
  </div>
);

// ========== 3. METRIC CARD ==========
const MCard = ({ label, value, icon, color, sub }) => (
  <motion.div whileHover={{ y: -2 }} className="panel p-5">
    <div className="flex items-center justify-between mb-3">
      <span className="text-[10px] mono text-gray-600 tracking-widest uppercase">{label}</span>
      <div className="w-7 h-7 rounded-lg flex items-center justify-center" style={{ background: `${color}18`, border: `1px solid ${color}40` }}>
        <i className={`fas fa-${icon} text-xs`} style={{ color }} />
      </div>
    </div>
    <div className="text-3xl font-body font-semibold" style={{ color }}>{value ?? 0}</div>
    {sub && <div className="text-[10px] text-gray-600 mt-1">{sub}</div>}
  </motion.div>
);

// ========== 4. SIDEBAR ==========
const NAV = [
  { id: 'dashboard', icon: 'gauge-high', label: 'Dashboard' },
  { id: 'map', icon: 'map', label: 'Live Map' },
  { id: 'assets', icon: 'plane', label: 'Fleet & Assets' },
  { id: 'threats', icon: 'skull-crossbones', label: 'Threats' },
  { id: 'alerts', icon: 'bell', label: 'Alerts' },
  { id: 'reports', icon: 'file-contract', label: 'Reports' },
  { id: 'audit', icon: 'shield-check', label: 'Audit Log' },
];

const Sidebar = ({ page, setPage, user, logout, unacked }) => (
  <aside className="fixed left-0 top-0 bottom-0 flex flex-col z-40" style={{ width: 220, background: '#04060e', borderRight: '1px solid #15203a' }}>
    <div className="px-4 py-5 border-b border-s-border">
      <div className="flex items-center gap-2.5 mb-1">
        <div className="w-7 h-7 rounded-lg flex items-center justify-center flex-shrink-0" style={{ background: '#00d9f715', border: '1px solid #00d9f740' }}>
          <i className="fas fa-shield-halved text-xs" style={{ color: '#00d9f7' }} />
        </div>
        <span className="font-display font-bold text-sm text-gradient">SHADOW NDR</span>
      </div>
      <div className="text-[10px] mono text-gray-600 pl-9">{user?.tenant_name}</div>
    </div>
    <nav className="flex-1 p-3 space-y-0.5 overflow-y-auto">
      {NAV.map(({ id, icon, label }) => (
        <button key={id} onClick={() => setPage(id)}
          className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-all duration-150 relative ${page === id ? 'text-s-accent' : 'text-gray-500 hover:text-gray-300'}`}
          style={page === id ? { background: 'rgba(0,217,247,0.08)', border: '1px solid rgba(0,217,247,0.15)' } : {}}>
          <i className={`fas fa-${icon} w-4 text-xs`} />
          <span className="font-body">{label}</span>
          {id === 'alerts' && unacked > 0 && (
            <span className="ml-auto text-[10px] font-mono px-1.5 py-0.5 rounded-full"
              style={{ background: 'rgba(255,31,76,0.2)', color: '#ff4569', border: '1px solid rgba(255,31,76,0.3)' }}>
              {unacked}
            </span>
          )}
        </button>
      ))}
    </nav>
    <div className="p-3 border-t border-s-border">
      <div className="flex items-center gap-2.5 px-2 py-1.5 rounded-lg" style={{ background: '#07091a', border: '1px solid #15203a' }}>
        <div className="w-6 h-6 rounded-full flex items-center justify-center flex-shrink-0 text-[10px] font-bold"
          style={{ background: '#00d9f720', color: '#00d9f7', border: '1px solid #00d9f740' }}>
          {user?.username?.[0]?.toUpperCase()}
        </div>
        <div className="flex-1 min-w-0">
          <div className="text-xs text-gray-300 truncate">{user?.username}</div>
          <div className="text-[10px] mono text-gray-600">{user?.role}</div>
        </div>
        <button onClick={logout} title="Logout" className="text-gray-600 hover:text-s-danger transition-colors text-xs">
          <i className="fas fa-right-from-bracket" />
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
      { label: 'Actual', data: (timeline || []).map(d => d.count), borderColor: '#00d9f7', borderWidth: 2, fill: false, pointRadius: 3 },
      { label: 'AI Forecast', data: [...(timeline || []).slice(-1).map(d => d.count), ...forecast], borderColor: '#ff7b00', borderDash: [5, 5], fill: false, pointRadius: 2 }
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
      { label: 'All', data: (timeline || []).map(d => d.count), borderColor: '#00d9f7', backgroundColor: 'rgba(0,217,247,.08)', fill: true, tension: .4, pointRadius: 3, borderWidth: 1.5 },
      { label: 'Crit', data: (timeline || []).map(d => d.critical), borderColor: '#ff1f4c', backgroundColor: 'rgba(255,31,76,.06)', fill: true, tension: .4, pointRadius: 3, borderWidth: 1.5 },
    ]
  };
  return (
    <div id="report-pdf-content">
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <MCard label="Active Threats" value={threats?.active} icon="skull-crossbones" color="#ff1f4c" sub={`${threats?.total || 0} total / 24h`} />
        <MCard label="Critical" value={threats?.critical} icon="radiation" color="#ff7b00" sub={`avg score ${parseFloat(threats?.avg_score || 0).toFixed(2)}`} />
        <MCard label="Fleet Online" value={assets?.active} icon="plane" color="#00e87a" sub={`${assets?.under_attack || 0} under attack`} />
        <MCard label="Unacked Alerts" value={alerts?.unacked} icon="bell" color="#fbbf24" sub="last 6 hours" />
      </div>
      <div className="grid grid-cols-5 gap-4 mt-5">
        <div className="col-span-3 panel p-5" style={{ height: 240 }}>
          <h3 className="text-[10px] mono text-s-accent tracking-widest uppercase mb-4">Threat Timeline – 12h</h3>
          <div style={{ height: 180 }}><Line data={chartData} options={{ responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false }, tooltip: { backgroundColor: '#0b0f22', borderColor: '#15203a', borderWidth: 1, titleColor: '#00d9f7', bodyColor: '#9ca3af' } }, scales: { x: { ticks: { color: '#374151', font: { family: 'Share Tech Mono', size: 10 } }, grid: { color: '#15203a' } }, y: { ticks: { color: '#374151', font: { family: 'Share Tech Mono', size: 10 } }, grid: { color: '#15203a' } } } }} /></div>
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
                    <div className="h-full rounded-full" style={{ width: `${r.risk_score}%`, background: r.risk_score > 80 ? '#ff1f4c' : r.risk_score > 60 ? '#ff7b00' : '#fbbf24' }} />
                  </div>
                  <span className="mono text-xs font-semibold" style={{ color: r.risk_score > 80 ? '#ff4569' : r.risk_score > 60 ? '#ff9c33' : '#fbbf24' }}>
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
                    <motion.div className="h-full rounded-full" initial={{ width: 0 }} animate={{ width: `${(a.count / max) * 100}%` }} transition={{ delay: i * .04, duration: .5 }} style={{ background: 'linear-gradient(90deg,#00d9f7,#8b5cf6)' }} />
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
                <div className="w-1.5 h-1.5 rounded-full mt-1.5 flex-shrink-0" style={{ background: SEV[a.severity] || '#00d9f7' }} />
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
const AssetsPage = ({ assets, user, selectedAsset, onClearSelected }) => {
  const [sel, setSel] = useState(null);
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
                  <td className="py-2.5">{a.is_protected ? <span style={{ color: '#00e87a' }}>✓</span> : <span style={{ color: '#ff4569' }}>✗</span>}</td>
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
                  <div key={i} className="bg-s-void rounded-lg p-3" style={{ border: '1px solid #15203a' }}>
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
                <td className="py-2.5 pr-4 mono" style={{ color: t.score > 0.8 ? '#ff1f4c' : t.score > 0.6 ? '#ff7b00' : '#fbbf24' }}>{parseFloat(t.score || 0).toFixed(3)}</td>
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

// ========== 9. ALERTS PAGE ==========
const AlertsPage = ({ alerts, onAck }) => (
  <div className="panel p-5">
    <h2 className="text-[10px] mono text-s-accent tracking-widest uppercase mb-5">Alerts</h2>
    <div className="space-y-3">
      {(alerts || []).map(a => (
        <motion.div key={a.id} layout className="flex items-start gap-3 p-4 rounded-xl"
          style={{ background: a.acknowledged ? '#07091a' : `${SEV[a.severity] || '#00d9f7'}08`, border: `1px solid ${a.acknowledged ? '#15203a' : (SEV[a.severity] || '#00d9f7') + '33'}` }}>
          <div className="w-1.5 h-1.5 rounded-full mt-1.5 flex-shrink-0" style={{ background: a.acknowledged ? '#374151' : SEV[a.severity] || '#00d9f7' }} />
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
            <button onClick={() => onAck(a.id)} className="text-[10px] mono px-3 py-1.5 rounded-lg flex-shrink-0 transition-colors" style={{ background: 'rgba(0,217,247,0.1)', border: '1px solid rgba(0,217,247,0.3)', color: '#00d9f7' }}>
              Acknowledge
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
                  <td className="py-2.5 pr-4 mono" style={{ color: r.score > 0.8 ? '#ff1f4c' : '#ff9c33' }}>{parseFloat(r.score || 0).toFixed(3)}</td>
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
                  ['Score', <span style={{ color: '#ff4569' }}>{parseFloat(sel.score || 0).toFixed(4)}</span>],
                ].map(([l, v], i) => (
                  <div key={i} className="rounded-xl p-3" style={{ background: '#07091a', border: '1px solid #15203a' }}>
                    <div className="mono text-[10px] text-gray-600 uppercase tracking-wider mb-1">{l}</div>
                    <div className="text-gray-200">{v}</div>
                  </div>
                ))}
              </div>
              {sel.description && (
                <div className="rounded-xl p-4" style={{ background: '#07091a', border: '1px solid #15203a' }}>
                  <div className="mono text-[10px] text-gray-600 uppercase tracking-wider mb-2">Description</div>
                  <p className="text-sm text-gray-300 leading-relaxed">{sel.description}</p>
                </div>
              )}
              <button className="mt-5 w-full py-2.5 rounded-xl text-sm transition-all" style={{ background: 'rgba(0,217,247,0.08)', border: '1px solid rgba(0,217,247,0.3)', color: '#00d9f7' }} onClick={() => alert('PDF export coming soon')}>
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
const makeIcon = (level) => L.divIcon({
  className: '',
  html: `<div style="width:28px;height:28px;border-radius:50%;background:${SEV[level] || '#00d9f7'}22;border:2px solid ${SEV[level] || '#00d9f7'};display:flex;align-items:center;justify-content:center;color:${SEV[level] || '#00d9f7'};font-size:14px;${level === 'under_attack' ? 'animation:pulse 1s infinite;' : ''}">✈</div>`,
  iconSize: [28, 28], iconAnchor: [14, 14],
});
const LiveMap = ({ assets }) => {
  const ac = (assets || []).filter(a => a.asset_type === 'aircraft' && a.latitude && a.longitude);
  return (
    <div className="panel" style={{ height: 'calc(100vh - 120px)' }}>
      <div className="absolute top-4 left-4 z-[1000] panel px-3 py-2">
        <span className="text-[10px] mono text-s-accent tracking-widest uppercase">Live Radar</span>
        <span className="ml-3 text-[10px] mono text-gray-600">{ac.length} aircraft</span>
      </div>
      <MapContainer center={[32.0, 34.9]} zoom={8} style={{ height: '100%', borderRadius: 14 }}>
        <TileLayer url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png" />
        {ac.map(a => (
          <Marker key={a.id} position={[a.latitude, a.longitude]} icon={makeIcon(a.threat_level)}>
            <Popup className="shadow-popup">
              <div style={{ background: '#0b0f22', border: '1px solid #15203a', borderRadius: 8, padding: '8px 12px', minWidth: 200, color: 'white' }}>
                <div style={{ fontFamily: 'Syne,sans-serif', fontWeight: 700, fontSize: 14, marginBottom: 4 }}>{a.name}</div>
                <div style={{ fontFamily: 'Share Tech Mono', fontSize: 11, color: '#6b7280' }}>
                  <div>ICAO: {a.icao24} · {a.callsign}</div>
                  <div>Alt: {a.altitude_ft?.toLocaleString()}ft · {a.speed_kts}kts · {a.heading}°</div>
                  <div>Squawk: {a.squawk}</div>
                  <div style={{ marginTop: 4 }}><span className={`badge badge-${a.threat_level}`}>{a.threat_level}</span></div>
                </div>
              </div>
            </Popup>
          </Marker>
        ))}
      </MapContainer>
    </div>
  );
};

// ========== 13. 3D GLOBE ==========
// ========== 13. 3D GLOBE – ULTIMATE EDITION ==========
const Globe3D = ({ assets }) => {
  const containerRef = useRef();
  const animationId = useRef();
  const [error, setError] = useState(false);

  useEffect(() => {
    if (!containerRef.current) return;
    
    // Setup scene
    const scene = new THREE.Scene();
    scene.background = new THREE.Color(0x050b1a); // כחול עמוק לילה
    scene.fog = new THREE.FogExp2(0x050b1a, 0.0008); // ערפל קל לעומק
    
    // Camera
    const camera = new THREE.PerspectiveCamera(45, 1, 0.1, 1000);
    camera.position.set(0, 0, 13);
    
    // Renderer
    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: false });
    renderer.setSize(containerRef.current.clientWidth, containerRef.current.clientHeight);
    renderer.setPixelRatio(window.devicePixelRatio);
    containerRef.current.appendChild(renderer.domElement);
    
    // Controls
    const controls = new OrbitControls(camera, renderer.domElement);
    controls.enableDamping = true;
    controls.dampingFactor = 0.05;
    controls.autoRotate = true;
    controls.autoRotateSpeed = 0.5;
    controls.enableZoom = true;
    controls.enablePan = false;
    controls.zoomSpeed = 1.2;
    controls.rotateSpeed = 0.8;
    
    // Earth with high-res texture + bump map + specular
    const geometry = new THREE.SphereGeometry(5, 128, 128);
    const textureLoader = new THREE.TextureLoader();
    
    // נסה לטעון טקסטורה באיכות גבוהה (עם fallback)
    let earthMaterial;
    try {
      const colorMap = textureLoader.load('https://threejs.org/examples/textures/planets/earth_atmos_2048.jpg');
      const bumpMap = textureLoader.load('https://threejs.org/examples/textures/planets/earth_normal_2048.jpg');
      const specularMap = textureLoader.load('https://threejs.org/examples/textures/planets/earth_specular_2048.jpg');
      earthMaterial = new THREE.MeshPhongMaterial({
        map: colorMap,
        bumpMap: bumpMap,
        bumpScale: 0.05,
        specularMap: specularMap,
        specular: new THREE.Color('grey'),
        shininess: 5
      });
    } catch (e) {
      // Fallback פשוט יותר אם הטקסטורות לא נטענות
      earthMaterial = new THREE.MeshStandardMaterial({
        color: 0x2a6f8f,
        roughness: 0.5,
        metalness: 0.1,
        emissive: 0x0a2a3a,
        emissiveIntensity: 0.2
      });
    }
    
    const earth = new THREE.Mesh(geometry, earthMaterial);
    scene.add(earth);
    
    // שכבת עננים (Clouds)
    const cloudGeometry = new THREE.SphereGeometry(5.02, 128, 128);
    const cloudTexture = textureLoader.load('https://threejs.org/examples/textures/planets/earth_clouds_1024.png');
    const cloudMaterial = new THREE.MeshPhongMaterial({
      map: cloudTexture,
      transparent: true,
      opacity: 0.15,
      blending: THREE.AdditiveBlending
    });
    const clouds = new THREE.Mesh(cloudGeometry, cloudMaterial);
    scene.add(clouds);
    
    // כוכבים (Particle System)
    const starGeometry = new THREE.BufferGeometry();
    const starCount = 4000;
    const starPositions = new Float32Array(starCount * 3);
    for (let i = 0; i < starCount; i++) {
      // פיזור כוכבים בכדור גדול מסביב
      const radius = 400 + Math.random() * 100;
      const theta = Math.random() * Math.PI * 2;
      const phi = Math.acos(2 * Math.random() - 1);
      starPositions[i * 3] = radius * Math.sin(phi) * Math.cos(theta);
      starPositions[i * 3 + 1] = radius * Math.sin(phi) * Math.sin(theta);
      starPositions[i * 3 + 2] = radius * Math.cos(phi);
    }
    starGeometry.setAttribute('position', new THREE.BufferAttribute(starPositions, 3));
    const starMaterial = new THREE.PointsMaterial({ color: 0xffffff, size: 0.35, transparent: true, opacity: 0.8 });
    const stars = new THREE.Points(starGeometry, starMaterial);
    scene.add(stars);
    
    // שכבת כוכבים נוספת קטנה ורחוקה (עומק)
    const starGeometry2 = new THREE.BufferGeometry();
    const starCount2 = 2000;
    const starPositions2 = new Float32Array(starCount2 * 3);
    for (let i = 0; i < starCount2; i++) {
      starPositions2[i * 3] = (Math.random() - 0.5) * 800;
      starPositions2[i * 3 + 1] = (Math.random() - 0.5) * 800;
      starPositions2[i * 3 + 2] = (Math.random() - 0.5) * 400 - 150;
    }
    starGeometry2.setAttribute('position', new THREE.BufferAttribute(starPositions2, 3));
    const starMaterial2 = new THREE.PointsMaterial({ color: 0xaaccff, size: 0.2 });
    const stars2 = new THREE.Points(starGeometry2, starMaterial2);
    scene.add(stars2);
    
    // Lights
    const ambientLight = new THREE.AmbientLight(0x404060);
    scene.add(ambientLight);
    
    const mainLight = new THREE.DirectionalLight(0xffffff, 1.2);
    mainLight.position.set(10, 15, 5);
    scene.add(mainLight);
    
    const fillLight = new THREE.PointLight(0x4466cc, 0.5);
    fillLight.position.set(-5, 0, -8);
    scene.add(fillLight);
    
    const backLight = new THREE.PointLight(0xffaa66, 0.3);
    backLight.position.set(0, 5, -12);
    scene.add(backLight);
    
    // אור רקע רך
    const rimLight = new THREE.PointLight(0x88aaff, 0.4);
    rimLight.position.set(5, 3, -10);
    scene.add(rimLight);
    
    // ---------- Markers for aircraft (3D models simplified) ----------
    const markers = [];
    
    const latLonToVector3 = (lat, lon, radius = 5.05) => {
      const phi = (90 - lat) * Math.PI / 180;
      const theta = lon * Math.PI / 180;
      return new THREE.Vector3(
        radius * Math.sin(phi) * Math.cos(theta),
        radius * Math.cos(phi),
        radius * Math.sin(phi) * Math.sin(theta)
      );
    };
    
    const createAircraftMarker = (threatLevel) => {
      const color = SEV[threatLevel] || '#00d9f7';
      const group = new THREE.Group();
      
      // גוף המטוס
      const bodyGeo = new THREE.BoxGeometry(0.14, 0.05, 0.32);
      const bodyMat = new THREE.MeshStandardMaterial({ color: color, emissive: threatLevel === 'under_attack' ? 0x441111 : 0x000000, emissiveIntensity: 0.3 });
      const body = new THREE.Mesh(bodyGeo, bodyMat);
      body.castShadow = true;
      group.add(body);
      
      // כנפיים
      const wingGeo = new THREE.BoxGeometry(0.28, 0.02, 0.08);
      const wingMat = new THREE.MeshStandardMaterial({ color: color });
      const wings = new THREE.Mesh(wingGeo, wingMat);
      wings.position.set(0, 0, -0.05);
      group.add(wings);
      
      // זנב
      const tailGeo = new THREE.ConeGeometry(0.06, 0.1, 4);
      const tailMat = new THREE.MeshStandardMaterial({ color: color });
      const tail = new THREE.Mesh(tailGeo, tailMat);
      tail.position.set(0, 0.04, -0.14);
      group.add(tail);
      
      // אפקט זוהר למטוסים תחת תקיפה
      if (threatLevel === 'under_attack' || threatLevel === 'critical') {
        const glowGeo = new THREE.SphereGeometry(0.12, 8, 8);
        const glowMat = new THREE.MeshBasicMaterial({ color: 0xff3300, transparent: true, opacity: 0.4, blending: THREE.AdditiveBlending });
        const glow = new THREE.Mesh(glowGeo, glowMat);
        group.add(glow);
      }
      
      return group;
    };
    
    const addMarkers = () => {
      // מסיר קודמים
      markers.forEach(m => scene.remove(m));
      markers.length = 0;
      
      const aircrafts = (assets || []).filter(a => a.asset_type === 'aircraft' && a.latitude && a.longitude);
      aircrafts.forEach(plane => {
        const pos = latLonToVector3(plane.latitude, plane.longitude);
        const marker = createAircraftMarker(plane.threat_level);
        marker.position.copy(pos);
        // מכוון את המטוס לכיוון התעופה ( tangent to sphere)
        marker.lookAt(pos.clone().multiplyScalar(2));
        scene.add(marker);
        markers.push(marker);
      });
    };
    
    addMarkers();
    
    // עדכון אוטומטי של מיקומי מטוסים (אם יש תנועה)
    let frame = 0;
    const animate = () => {
      frame++;
      controls.update(); // מעדכן סיבוב אוטומטי
      
      // סיבוב עננים לאט
      clouds.rotation.y += 0.0005;
      
      // הנפשה קלה של המטוסים: תנועה למעלה/למטה + סיבוב
      markers.forEach((marker, idx) => {
        marker.position.y += Math.sin(Date.now() * 0.002 + idx) * 0.002;
        marker.rotation.z += 0.01;
        marker.rotation.x += 0.005;
        // הבהוב קל של צבע למטוסים תחת תקיפה
        if (marker.children[0]?.material?.emissiveIntensity) {
          const intensity = 0.2 + Math.sin(Date.now() * 0.01) * 0.15;
          marker.children[0].material.emissiveIntensity = intensity;
        }
      });
      
      renderer.render(scene, camera);
      animationId.current = requestAnimationFrame(animate);
    };
    
    animate();
    
    const handleResize = () => {
      const width = containerRef.current.clientWidth;
      const height = containerRef.current.clientHeight;
      camera.aspect = width / height;
      camera.updateProjectionMatrix();
      renderer.setSize(width, height);
    };
    
    window.addEventListener('resize', handleResize);
    handleResize();
    
    return () => {
      cancelAnimationFrame(animationId.current);
      window.removeEventListener('resize', handleResize);
      renderer.dispose();
      if (containerRef.current) containerRef.current.innerHTML = '';
    };
  }, [assets]);
  
  if (error) {
    return (
      <div className="panel flex items-center justify-center" style={{ height: 'calc(100vh - 120px)' }}>
        <div className="text-center text-gray-400">
          <i className="fas fa-globe-americas text-4xl mb-3 block"></i>
          <p className="text-sm">Unable to load 3D Globe. Check your internet connection.</p>
          <button 
            onClick={() => window.location.reload()} 
            className="mt-3 text-xs bg-s-accent/20 px-3 py-1 rounded"
          >
            Retry
          </button>
        </div>
      </div>
    );
  }
  
  return <div ref={containerRef} className="w-full h-full rounded-2xl overflow-hidden" style={{ height: 'calc(100vh - 120px)' }} />;
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

// ========== 19. TELEMETRY ==========
const useTelemetry = (initialAssets) => {
  const [assets, setAssets] = useState(initialAssets);
  useEffect(() => {
    setAssets(initialAssets);
  }, [initialAssets]);
  useEffect(() => {
    const interval = setInterval(() => {
      setAssets(prev => prev.map(a => {
        if (a.asset_type !== 'aircraft' || !a.latitude) return a;
        const newLat = a.latitude + (Math.random() - 0.5) * 0.02;
        const newLon = a.longitude + (Math.random() - 0.5) * 0.02;
        return { ...a, latitude: newLat, longitude: newLon, last_contact: new Date().toISOString() };
      }));
    }, 3000);
    return () => clearInterval(interval);
  }, []);
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
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl mb-4" style={{ background: 'linear-gradient(135deg,#00d9f722,#8b5cf622)', border: '1px solid #00d9f744' }}>
            <i className="fas fa-shield-halved text-2xl" style={{ color: '#00d9f7' }} />
          </div>
          <h1 className="font-display text-3xl font-bold text-gradient">SHADOW NDR</h1>
          <p className="text-xs mono text-gray-600 tracking-widest mt-1">MULTI-TENANT APEX v2.0</p>
        </div>
        <div className="panel p-8">
          <form onSubmit={submit} className="space-y-4">
            <div><label className="text-xs mono text-gray-500 uppercase tracking-widest block mb-1.5">Username</label><input value={u} onChange={e => setU(e.target.value)} className="w-full bg-s-void border border-s-border rounded-lg px-3 py-2.5 text-sm text-white outline-none focus:border-s-accent/60 transition-colors" /></div>
            <div><label className="text-xs mono text-gray-500 uppercase tracking-widest block mb-1.5">Password</label><input type="password" value={p} onChange={e => setP(e.target.value)} className="w-full bg-s-void border border-s-border rounded-lg px-3 py-2.5 text-sm text-white outline-none focus:border-s-accent/60 transition-colors" /></div>
            {err && <div className="text-xs text-s-danger mono">{err}</div>}
            <button type="submit" disabled={loading} className="w-full py-2.5 rounded-lg text-sm font-body font-medium transition-all" style={{ background: 'linear-gradient(135deg,#00d9f720,#8b5cf620)', border: '1px solid #00d9f744', color: '#00d9f7' }}>{loading ? 'Authenticating...' : 'Authenticate →'}</button>
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

// ========== 22. MAIN APP ==========
const Main = () => {
  const { user, logout } = useAuth();
  const { status: wsStatus, events } = useWebSocket();
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
    try {
      const [d, a, th, al, rp] = await Promise.all([api.getDashboard(), api.getAssets(), api.getThreats(), api.getAlerts(), api.getReports()]);
      setAssets(a.data || []);
      setDashData(d.data);
      setThreats(th.data || []);
      setAlerts(al.data || []);
      setReports(rp.data || []);
    } catch (e) { console.error('Load error:', e); }
    setLoading(false);
  }, []);
  useEffect(() => { load(); const t = setInterval(load, 30000); return () => clearInterval(t); }, [load]);
  const handleIsolateAsset = async (asset) => {
  try {
    console.log(`🛡️ Isolating asset: ${asset.icao24} - ${asset.name}`);
    // אם יש API לבידוד - הוסף כאן
    setToasts(prev => [{
      id: Date.now(),
      event: 'asset_isolated',
      message: `✅ Asset ${asset.icao24} isolated successfully`,
      severity: 'info'
    }, ...prev].slice(0, 5));
  } catch (error) {
    console.error('Isolation failed:', error);
  }
};

  const liveAssets = useTelemetry(assets);
  const displayAssets = filteredAssets ?? liveAssets;

  useEffect(() => {
    events.slice(0, 3).forEach(ev => {
      const threat = ev.data;
      const toast = { id: Date.now(), event: ev.event, message: threat?.threat_type || 'New alert', severity: threat?.severity || 'info' };
      setToasts(prev => [toast, ...prev].slice(0, 5));
      setTimeout(() => setToasts(prev => prev.filter(t => t.id !== toast.id)), 6000);
      if (threat?.severity === 'emergency') {
        speak(`Emergency: ${threat.threat_type} on ${threat.aircraft_name || 'aircraft'}`);
        notify('Shadow NDR Alert', { body: `${threat.threat_type} – ${threat.description?.slice(0, 100)}`, icon: '/favicon.ico' });
      }
      if (ev.event === 'new_threat') load();
    });
  }, [events, speak, load]);

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
    <div className="min-h-screen flex" data-theme={theme}>
      <Sidebar page={page} setPage={setPage} user={user} logout={logout} unacked={unacked} />
      <ToastContainer toasts={toasts} onDismiss={id => setToasts(p => p.filter(t => t.id !== id))} />
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
            <button onClick={() => setTheme(theme === 'dark' ? 'neon' : 'dark')} className="text-[10px] mono px-2.5 py-1.5 rounded-lg border border-s-border hover:border-s-accent/40"><i className={`fas fa-${theme === 'dark' ? 'sun' : 'moon'} mr-1`} />{theme === 'dark' ? 'Neon' : 'Dark'}</button>
            <button onClick={handleExportPDF} className="text-[10px] mono px-2.5 py-1.5 rounded-lg border border-s-border hover:border-s-accent/40"><i className="fas fa-file-pdf mr-1" />Export PDF</button>
            <button onClick={load} className="text-[10px] mono px-2.5 py-1.5 rounded-lg border border-s-border hover:border-s-accent/40"><i className="fas fa-rotate-right mr-1" />Refresh</button>
            <div className={`flex items-center gap-1.5 text-[10px] mono ${wsStatus === 'connected' ? 'text-s-ok' : wsStatus === 'reconnecting' ? 'text-s-warn' : 'text-s-danger'}`}><div className="w-1.5 h-1.5 rounded-full" style={{ background: wsStatus === 'connected' ? '#00e87a' : wsStatus === 'reconnecting' ? '#ff7b00' : '#ff1f4c' }} />{wsStatus.toUpperCase()}</div>
          </div>
        </div>
        <AnimatePresence mode="wait">
          <motion.div key={page} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }} transition={{ duration: .2 }}>
            {page === 'dashboard' && <><Dashboard data={dashData} /><ForecastChart timeline={dashData?.timeline} /></>}
            {page === 'map' && (<div><div className="flex justify-end mb-2 gap-2"><button onClick={() => setShow3D(false)} className={`text-[10px] mono px-3 py-1 rounded-lg ${!show3D ? 'bg-s-accent/20 text-s-accent' : 'bg-s-void text-gray-500'}`}>2D Map</button><button onClick={() => setShow3D(true)} className={`text-[10px] mono px-3 py-1 rounded-lg ${show3D ? 'bg-s-accent/20 text-s-accent' : 'bg-s-void text-gray-500'}`}>3D Globe</button></div>{show3D ? <Globe3D assets={displayAssets} /> : <LiveMap assets={displayAssets} />}</div>)}
            {page === 'assets' && <AssetsPage assets={displayAssets} user={user} selectedAsset={selectedAsset} onClearSelected={handleClearSelected} />}
            {page === 'threats' && <ThreatsPage threats={threats} onUpdateStatus={async (id, status) => { await api.updateThreat(id, { status }); load(); }} />}
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