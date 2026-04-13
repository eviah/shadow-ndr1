import { useEffect, useRef, useState } from 'react';
import io from 'socket.io-client';

export const useWebSocket = () => {
    const [status, setStatus] = useState('disconnected');
    const [events, setEvents] = useState([]);
    const socketRef = useRef(null);

    useEffect(() => {
        // קח את הטוקן מה-localStorage
        const token = localStorage.getItem('accessToken');
        
        if (!token) {
            console.log('[WS] No token found, skipping connection');
            return;
        }

        console.log('[WS] Connecting with token:', token.substring(0, 50) + '...');

        // התחבר ל-Socket.IO
        const socket = io('http://localhost:3001', {
            auth: { token },
            transports: ['websocket', 'polling'],
            reconnection: true,
            reconnectionAttempts: 10,
            reconnectionDelay: 1000,
            reconnectionDelayMax: 5000,
            timeout: 20000,
        });

        // אירועי חיבור
        socket.on('connect', () => {
            console.log('[WS] ✅ Connected to server');
            setStatus('connected');
        });

        socket.on('disconnect', (reason) => {
            console.log('[WS] ❌ Disconnected:', reason);
            setStatus('disconnected');
        });

        socket.on('connect_error', (error) => {
            console.error('[WS] Connection error:', error.message);
            setStatus('error');
        });

        socket.on('connected', (data) => {
            console.log('[WS] Server confirmation:', data);
        });

        // אירועי נתונים
        socket.on('new_threat', (threat) => {
            console.log('[WS] 🚨 New threat:', threat);
            setEvents(prev => [{ 
                event: 'new_threat', 
                data: threat, 
                timestamp: Date.now() 
            }, ...prev].slice(0, 100));
        });

        socket.on('new_alert', (alert) => {
            console.log('[WS] 🔔 New alert:', alert);
            setEvents(prev => [{ 
                event: 'new_alert', 
                data: alert, 
                timestamp: Date.now() 
            }, ...prev].slice(0, 100));
        });

        socket.on('threatsCount', (data) => {
            console.log('[WS] 📊 Threats count:', data);
        });

        socket.on('error', (error) => {
            console.error('[WS] Server error:', error);
        });

        socketRef.current = socket;

        // ניקוי בהרס הקומפוננטה
        return () => {
            console.log('[WS] Cleaning up connection');
            if (socketRef.current) {
                socketRef.current.disconnect();
                socketRef.current = null;
            }
        };
    }, []);

    // פונקציה לשליחת הודעות
    const send = (event, data) => {
        if (socketRef.current && status === 'connected') {
            socketRef.current.emit(event, data);
        } else {
            console.warn(`[WS] Cannot send ${event}, not connected`);
        }
    };

    return { status, events, send };
};