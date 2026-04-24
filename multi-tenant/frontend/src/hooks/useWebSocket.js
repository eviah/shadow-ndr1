import { useEffect, useRef, useState, useCallback } from 'react';
import io from 'socket.io-client';

/**
 * WebSocket hook — exposes:
 *   status        connect state
 *   events        rolling event log (bounded to 100)
 *   send(evt,d)   emit to server
 *   on(evt, cb)   subscribe to a server event; returns unsubscribe fn
 *   socket        raw socket.io instance for advanced use
 *
 * Server emits we care about:
 *   threat:new         a fresh active threat (first detection)
 *   threat:update      an existing active threat extended (dedupe hit)
 *   threat:resolved    sweeper auto-closed an attack
 *   asset:position     simulator position update
 *   asset:threat_level asset threat_level transitioned
 *   new_threat         legacy alias for threat:new (kept for back-compat)
 *   new_alert          high-severity alert creation
 */
const MIRRORED_EVENTS = [
    'new_threat', 'new_alert',
    'threat:new', 'threat:update', 'threat:resolved',
    'asset:position', 'asset:threat_level',
];

export const useWebSocket = () => {
    const [status, setStatus] = useState('disconnected');
    const [events, setEvents] = useState([]);
    const socketRef = useRef(null);
    const listenersRef = useRef(new Map()); // event → Set<cb>

    useEffect(() => {
        const token = localStorage.getItem('accessToken');
        if (!token) return;

        const socket = io('http://localhost:3001', {
            auth: { token },
            transports: ['websocket', 'polling'],
            reconnection: true,
            reconnectionAttempts: 10,
            reconnectionDelay: 1000,
            reconnectionDelayMax: 5000,
            timeout: 20000,
        });

        socket.on('connect',        () => setStatus('connected'));
        socket.on('disconnect',     () => setStatus('disconnected'));
        socket.on('connect_error',  () => setStatus('error'));

        // Mirror every interesting event into the rolling log AND fan out to
        // any .on() subscribers registered via this hook.
        for (const evt of MIRRORED_EVENTS) {
            socket.on(evt, (data) => {
                // Keep the log small; position updates are high-frequency so
                // we skip them in the log but still dispatch to listeners.
                if (evt !== 'asset:position') {
                    setEvents(prev => [{ event: evt, data, timestamp: Date.now() }, ...prev].slice(0, 100));
                }
                const subs = listenersRef.current.get(evt);
                if (subs) for (const cb of subs) { try { cb(data); } catch (e) { console.error(e); } }
            });
        }

        socketRef.current = socket;
        return () => { socket.disconnect(); socketRef.current = null; };
    }, []);

    const send = useCallback((event, data) => {
        if (socketRef.current?.connected) socketRef.current.emit(event, data);
    }, []);

    const on = useCallback((event, cb) => {
        let set = listenersRef.current.get(event);
        if (!set) { set = new Set(); listenersRef.current.set(event, set); }
        set.add(cb);
        return () => set.delete(cb);
    }, []);

    return { status, events, send, on, socket: socketRef };
};
