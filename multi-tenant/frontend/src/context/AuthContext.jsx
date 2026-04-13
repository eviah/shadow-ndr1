import React, { createContext, useContext, useState, useCallback, useEffect } from 'react';
import { login as apiLogin, refreshToken as apiRefresh, logout as apiLogout } from '../api/index.js';

const AuthCtx = createContext(null);
export const useAuth = () => useContext(AuthCtx);

export function AuthProvider({ children }) {
  const [user,  setUser]  = useState(() => { try { return JSON.parse(localStorage.getItem('user')||'null'); } catch{return null;} });
  const [ready, setReady] = useState(false);

  // Refresh on mount
  useEffect(() => {
    const rt = localStorage.getItem('refreshToken');
    if (!rt || user) { setReady(true); return; }
    apiRefresh(rt)
      .then(res => {
        localStorage.setItem('accessToken',  res.accessToken);
        localStorage.setItem('refreshToken', res.refreshToken);
      })
      .catch(() => { localStorage.clear(); setUser(null); })
      .finally(() => setReady(true));
  }, []);

  const login = useCallback(async (username, password) => {
    const res = await apiLogin(username, password);
    localStorage.setItem('accessToken',  res.accessToken);
    localStorage.setItem('refreshToken', res.refreshToken);
    localStorage.setItem('user', JSON.stringify(res.user));
    setUser(res.user);
    return res.user;
  }, []);

  const logout = useCallback(async () => {
    const rt = localStorage.getItem('refreshToken');
    await apiLogout(rt).catch(()=>{});
    localStorage.clear();
    setUser(null);
  }, []);

  if (!ready) return null;
  return <AuthCtx.Provider value={{ user, login, logout }}>{children}</AuthCtx.Provider>;
}
