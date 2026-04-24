import axios from 'axios';

const api = axios.create({ baseURL:'/api', timeout:10_000 });

api.interceptors.request.use(cfg => {
  const token = localStorage.getItem('accessToken');
  if (token) cfg.headers.Authorization = `Bearer ${token}`;
  return cfg;
});

api.interceptors.response.use(
  r => r.data,
  async err => {
    if (err.response?.status === 401 && !err.config._retry) {
      err.config._retry = true;
      const rt = localStorage.getItem('refreshToken');
      if (rt) {
        try {
          const res = await axios.post('/api/auth/refresh', { refreshToken: rt });
          localStorage.setItem('accessToken',  res.data.accessToken);
          localStorage.setItem('refreshToken', res.data.refreshToken);
          err.config.headers.Authorization = `Bearer ${res.data.accessToken}`;
          return api(err.config);
        } catch { localStorage.clear(); window.location.href='/login'; }
      }
    }
    return Promise.reject(err.response?.data || err);
  }
);

export const login         = (u,p)  => api.post('/auth/login',   { username:u, password:p });
export const refreshToken  = (rt)   => api.post('/auth/refresh', { refreshToken:rt });
export const logout        = (rt)   => api.post('/auth/logout',  { refreshToken:rt });
export const getMe         = ()     => api.get('/auth/me');

export const getDashboard  = ()     => api.get('/dashboard');
export const getAssets     = ()     => api.get('/assets');
export const getAsset      = (id)   => api.get(`/assets/${id}`);
export const getThreats    = (p={}) => api.get('/threats', { params:p });
export const getThreat     = (id)   => api.get(`/threats/${id}`);
export const updateThreat  = (id,b) => api.patch(`/threats/${id}/status`, b);
export const getAlerts     = ()     => api.get('/alerts');
export const ackAlert      = (id)   => api.post(`/alerts/${id}/acknowledge`);
export const getReports    = ()     => api.get('/reports');
export const getReport     = (id)   => api.get(`/reports/${id}`);

// ── Simulator control ────────────────────────────────────────────────────────
export const getAirports       = ()                  => api.get('/simulator/airports');
export const getFlights        = ()                  => api.get('/simulator/flights');
export const getFlight         = (id)                => api.get(`/simulator/flights/${id}`);
export const pauseFlight       = (id, paused)        => api.post(`/simulator/flights/${id}/pause`, { paused });
export const rerouteFlight     = (id, from, to)      => api.post(`/simulator/flights/${id}/route`, { from, to });
export const injectAttack      = (id, opts = {})     => api.post(`/simulator/flights/${id}/attack`, opts);
