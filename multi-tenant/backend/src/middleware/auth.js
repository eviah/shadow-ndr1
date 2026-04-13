import { verifyAccessToken } from '../services/auth.js';

export function authenticate(req, res, next) {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ success: false, error: 'No token provided' });
    }
    
    const token = authHeader.substring(7);
    const decoded = verifyAccessToken(token);
    
    if (!decoded) {
        return res.status(401).json({ success: false, error: 'Invalid or expired token' });
    }
    
    req.user = decoded;
    req.token = token;
    next();
}

export function requireRole(...roles) {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({ success: false, error: 'Unauthorized' });
        }
        
        if (roles.length > 0 && !roles.includes(req.user.role) && req.user.role !== 'admin') {
            return res.status(403).json({ success: false, error: 'Insufficient permissions' });
        }
        
        next();
    };
}

export function audit(action, resource) {
    return async (req, res, next) => {
        // Simple audit wrapper (can be extended)
        const start = Date.now();
        
        // Store original json method
        const originalJson = res.json;
        
        res.json = function(data) {
            const duration = Date.now() - start;
            console.log(`[AUDIT] ${action} on ${resource} by ${req.user?.username || 'unknown'} (${duration}ms)`);
            
            // Call original
            return originalJson.call(this, data);
        };
        
        next();
    };
}