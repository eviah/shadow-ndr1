// ========== COPILOT CHAT ULTIMATE - FULLY LOADED ==========
import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';

// ==================== GOOGLE SEARCH CONFIG ====================
// ⚠️ החלף את הערכים הבאים במפתחות האמיתיים שלך:
const GOOGLE_API_KEY = 'YOUR_GOOGLE_API_KEY'; // מפתח תקף מ-Google Cloud
const GOOGLE_CX      = 'c562863cf81214983';   // ה-CX שלך (תקין)
const GOOGLE_SEARCH_URL = 'https://www.googleapis.com/customsearch/v1';

// ==================== KNOWLEDGE BASE (RAG) – מידע עשיר ====================
const KNOWLEDGE_BASE = {
  threats: {
    'ads-b spoofing': {
      title: 'ADS-B Spoofing',
      description: 'הזרמת מטוסי רפאים למערכת המכ"ם על ידי שידור אותות ADS-B מזויפים',
      mitigation: 'BLOCK + ISOLATE + התרעה מיידית ל-ATC',
      severity: 'critical',
      remediation: 'חסום את כתובת ה-IP המקורית, בדוק מול מכ"ם משני, נתח דפוסי תעבורה'
    },
    ransomware: {
      title: 'Ransomware',
      description: 'הצפנת קבצים קריטיים במערכות הבקרה (ATC, תאורה, עיבוד מזוודות)',
      mitigation: 'ISOLATE + BACKUP + ניתוח פורנזי',
      severity: 'critical',
      remediation: 'בודד את המערכת הנגועה, שחזר מגיבוי, זהה וקטור חדירה'
    },
    'gps jamming': {
      title: 'GPS Jamming',
      description: 'שיבוש אותות GPS באזור שדה התעופה, מסכן ניווט מטוסים',
      mitigation: 'THROTTLE + מעבר ל-INS + ניטור',
      severity: 'high',
      remediation: 'עבור למערכות ניווט אינרציאליות, זיהוי מקור השיבוש'
    },
    'mode s hijack': {
      title: 'Mode S Hijack',
      description: 'השתלטות על תקשורת Mode S (Squawk 7500 - חטיפה)',
      mitigation: 'IMMEDIATE_ATC_ALERT + מעקב צמוד',
      severity: 'emergency',
      remediation: 'התרעה מיידית לבקרת הטיסה, ניתוח תעבורה, אימות squawk'
    },
    'acars injection': {
      title: 'ACARS Injection',
      description: 'הזרקת הודעות טרור או הודעות מטעה למערכת ACARS',
      mitigation: 'BLOCK + ALERT + אימות הודעה',
      severity: 'high',
      remediation: 'חסום מקור חשוד, אמת הודעות מול צוות קרקע'
    }
  },
  assets: {
    '4xeld': { type: 'Boeing 787 Dreamliner', airline: 'EL AL', year: 2019, icao24: '4XELD' },
    '4xabe': { type: 'Boeing 777-200ER', airline: 'EL AL', year: 2015, icao24: '4XABE' },
    '4xeca': { type: 'Boeing 737-900ER', airline: 'EL AL', year: 2018, icao24: '4XECA' },
    'isr001': { type: 'Airbus A320-200', airline: 'Israir', year: 2016, icao24: 'ISR001' },
    'arz001': { type: 'Airbus A321neo', airline: 'Arkia', year: 2022, icao24: 'ARZ001' }
  },
  procedures: {
    emergency: '📋 **נוהל חירום**:\n1. נתק את המערכת הנגועה מהרשת\n2. עדכן את SOC (Security Operations Center)\n3. התחל ניתוח פורנזי\n4. שחזר מגיבוי נקי\n5. תעד את האירוע',
    isolation: '📋 **נוהל בידוד**:\n1. בודד את ה-Asset המושפע\n2. חסום תעבורה נכנסת/יוצאת\n3. בדוק תלותיות קריטיות\n4. עדכן את כל הצוותים הרלוונטיים\n5. הפעל מערכות גיבוי',
    atc_alert: '📋 **נוהל התרעה ל-ATC**:\n1. שלח התרעה מיידית דרך מערכת ATC\n2. ספק את כל הפרטים (ICAO, מיקום, סוג איום)\n3. עקוב אחר תגובת הטייס\n4. הנחה לשימוש במכ"ם משני'
  },
  regulations: {
    icao: '📜 ICAO Annex 17 – אבטחת תעופה. מחייב דיווח על אירועי סייבר תוך 24 שעות.',
    faa: '📜 FAA AC 120-92B – נוהלי אבטחת סייבר לתעופה.',
    easa: '📜 EASA ED 2020/001 – דרישות אבטחת סייבר לכלי טיס.'
  }
};

// ==================== TRANSLATIONS (10 שפות) ====================
const LANGUAGES = {
  he: { name: 'עברית', flag: '🇮🇱', dir: 'rtl' },
  en: { name: 'English', flag: '🇬🇧', dir: 'ltr' },
  ar: { name: 'العربية', flag: '🇸🇦', dir: 'rtl' },
  es: { name: 'Español', flag: '🇪🇸', dir: 'ltr' },
  fr: { name: 'Français', flag: '🇫🇷', dir: 'ltr' },
  de: { name: 'Deutsch', flag: '🇩🇪', dir: 'ltr' },
  ru: { name: 'Русский', flag: '🇷🇺', dir: 'ltr' },
  zh: { name: '中文', flag: '🇨🇳', dir: 'ltr' },
  ja: { name: '日本語', flag: '🇯🇵', dir: 'ltr' },
  hi: { name: 'हिन्दी', flag: '🇮🇳', dir: 'ltr' }
};

const TRANSLATIONS = {
  greetings: {
    he: ['שלום! 👋 איך אפשר לעזור?', 'היי! 🚀 במה אוכל לסייע?', 'מה קורה? 😊'],
    en: ['Hello! 👋 How can I help?', 'Hey! 🚀 How can I assist?', 'Hi there! 😊'],
    ar: ['مرحبًا! 👋 كيف يمكنني المساعدة؟', 'أهلاً! 🚀 كيف يمكنني مساعدتك؟', 'مرحباً! 😊'],
    es: ['¡Hola! 👋 ¿Cómo puedo ayudar?', '¡Hola! 🚀 ¿En qué puedo asistir?', '¡Hola! 😊'],
    fr: ['Bonjour! 👋 Comment puis-je aider?', 'Salut! 🚀 Comment puis-je assister?', 'Bonjour! 😊'],
    de: ['Hallo! 👋 Wie kann ich helfen?', 'Hallo! 🚀 Wie kann ich behilflich sein?', 'Hallo! 😊'],
    ru: ['Здравствуйте! 👋 Чем могу помочь?', 'Привет! 🚀 Как я могу помочь?', 'Привет! 😊'],
    zh: ['你好！👋 我能帮你什么？', '嗨！🚀 我如何协助你？', '你好！😊'],
    ja: ['こんにちは！👋 どのように支援できますか？', 'こんにちは！🚀 何かお手伝いできますか？', 'こんにちは！😊'],
    hi: ['नमस्ते! 👋 मैं कैसे मदद कर सकता हूँ?', 'नमस्ते! 🚀 मैं कैसे सहायता कर सकता हूँ?', 'नमस्ते! 😊']
  },
  navigation: {
    he: { dashboard: ['דשבורד','ראשי'], map: ['מפה','עבור למפה','תפנה אותי למפה'], assets: ['מטוסים','נכסים'], threats: ['איומים','תקיפות'], alerts: ['התראות'], reports: ['דוחות'], audit: ['ביקורת'] },
    en: { dashboard: ['dashboard','home'], map: ['map','go to map'], assets: ['assets','fleet','aircraft'], threats: ['threats','attacks'], alerts: ['alerts'], reports: ['reports'], audit: ['audit'] },
    ar: { dashboard: ['لوحة القيادة'], map: ['خريطة','اذهب إلى الخريطة'], assets: ['الطائرات'], threats: ['التهديدات'], alerts: ['التنبيهات'], reports: ['التقارير'], audit: ['سجل التدقيق'] },
    es: { dashboard: ['tablero'], map: ['mapa','ir al mapa'], assets: ['aviones'], threats: ['amenazas'], alerts: ['alertas'], reports: ['informes'], audit: ['auditoría'] },
    fr: { dashboard: ['tableau de bord'], map: ['carte','aller à la carte'], assets: ['avions'], threats: ['menaces'], alerts: ['alertes'], reports: ['rapports'], audit: ['audit'] },
    de: { dashboard: ['Dashboard'], map: ['Karte','gehe zur Karte'], assets: ['Flugzeuge'], threats: ['Bedrohungen'], alerts: ['Alarme'], reports: ['Berichte'], audit: ['Prüfprotokoll'] },
    ru: { dashboard: ['панель'], map: ['карта','перейти к карте'], assets: ['самолеты'], threats: ['угрозы'], alerts: ['оповещения'], reports: ['отчеты'], audit: ['аудит'] },
    zh: { dashboard: ['仪表板'], map: ['地图','转到地图'], assets: ['飞机'], threats: ['威胁'], alerts: ['警报'], reports: ['报告'], audit: ['审计'] },
    ja: { dashboard: ['ダッシュボード'], map: ['地図','地図へ行く'], assets: ['航空機'], threats: ['脅威'], alerts: ['アラート'], reports: ['レポート'], audit: ['監査'] },
    hi: { dashboard: ['डैशबोर्ड'], map: ['नक्शा','नक्शे पर जाएं'], assets: ['विमान'], threats: ['खतरे'], alerts: ['अलर्ट'], reports: ['रिपोर्ट'], audit: ['ऑडिट'] }
  },
  fallbackMessages: {
    he: 'סליחה, לא הבנתי. אפשר לשאול על איומים, מטוסים, או פקודות כמו "עבור למפה", "חסום IP 1.2.3.4", "שלח התרעה ל-ATC".',
    en: 'Sorry, I didn\'t understand. You can ask about threats, aircraft, or commands like "go to map", "block IP 1.2.3.4", "send ATC alert".',
    ar: 'عذرًا، لم أفهم. يمكنك السؤال عن التهديدات أو الطائرات أو أوامر مثل "اذهب إلى الخريطة"، "حظر IP 1.2.3.4"، "إرسال تنبيه ATC".',
    es: 'Lo siento, no entendí. Puedes preguntar sobre amenazas, aviones o comandos como "ir al mapa", "bloquear IP 1.2.3.4", "enviar alerta ATC".',
    fr: 'Désolé, je n\'ai pas compris. Vous pouvez demander des menaces, des avions ou des commandes comme "aller à la carte", "bloquer IP 1.2.3.4", "envoyer alerte ATC".',
    de: 'Entschuldigung, nicht verstanden. Fragen Sie nach Bedrohungen, Flugzeugen oder Befehlen wie "gehe zur Karte", "blockiere IP 1.2.3.4", "ATC-Alarm senden".',
    ru: 'Извините, не понял. Спросите об угрозах, самолетах или командах: "перейти к карте", "заблокировать IP 1.2.3.4", "отправить оповещение ATC".',
    zh: '抱歉，我没理解。您可以询问威胁、飞机或命令，如“转到地图”、“阻止IP 1.2.3.4”、“发送ATC警报”。',
    ja: '申し訳ありません。脅威、航空機、または「地図へ行く」、「IP 1.2.3.4をブロック」、「ATCアラートを送信」などのコマンドを質問できます。',
    hi: 'क्षमा करें, मैं समझ नहीं पाया। आप खतरों, विमानों, या कमांड जैसे "नक्शे पर जाएं", "IP 1.2.3.4 ब्लॉक करें", "एटीसी अलर्ट भेजें" के बारे में पूछ सकते हैं।'
  }
};

// ==================== HELPER FUNCTIONS ====================
const uniqueId = () => `${Date.now()}-${Math.random()}-${performance.now()}`;

const detectLanguage = (text) => {
  if (/[\u0590-\u05FF]/.test(text)) return 'he';
  if (/[\u0600-\u06FF]/.test(text)) return 'ar';
  if (/[\u0400-\u04FF]/.test(text)) return 'ru';
  if (/[\u4e00-\u9fff]/.test(text)) return 'zh';
  if (/[\u3040-\u30FF]/.test(text)) return 'ja';
  if (/[\u0900-\u097F]/.test(text)) return 'hi';
  if (/[áéíóúñ¿¡]/i.test(text)) return 'es';
  if (/[àâçéèêëîïôûùüÿ]/i.test(text)) return 'fr';
  if (/[äöüß]/i.test(text)) return 'de';
  if (/[a-zA-Z]/.test(text)) return 'en';
  return 'he';
};

const searchKnowledge = (query) => {
  const results = [];
  const lower = query.toLowerCase();
  for (const [key, data] of Object.entries(KNOWLEDGE_BASE.threats)) {
    if (lower.includes(key) || lower.includes(data.title.toLowerCase())) results.push({ type: 'threat', key, ...data });
  }
  for (const [key, data] of Object.entries(KNOWLEDGE_BASE.assets)) {
    if (lower.includes(key)) results.push({ type: 'asset', key, ...data });
  }
  for (const [key, data] of Object.entries(KNOWLEDGE_BASE.procedures)) {
    if (lower.includes(key)) results.push({ type: 'procedure', content: data });
  }
  for (const [key, data] of Object.entries(KNOWLEDGE_BASE.regulations)) {
    if (lower.includes(key)) results.push({ type: 'regulation', content: data });
  }
  return results;
};

const detectNavigation = (text, lang) => {
  const lower = text.toLowerCase();
  const navMap = TRANSLATIONS.navigation;
  for (const l of [lang, 'en', 'he']) {
    if (navMap[l]) {
      for (const [page, phrases] of Object.entries(navMap[l])) {
        if (phrases.some(p => lower.includes(p.toLowerCase()))) return page;
      }
    }
  }
  return null;
};

const getQuickResponse = (text, lang) => {
  const lower = text.toLowerCase();
  if (/(hello|hi|hey|שלום|היי|مرحبا|hola|bonjour|hallo|привет|你好|こんにちは|नमस्ते)/i.test(lower))
    return TRANSLATIONS.greetings[lang]?.[0] || 'Hello! 👋';
  if (/(how are you|what's up|מה נשמע|как дела|¿cómo estás|comment ça va|wie geht's|आप कैसे हैं)/i.test(lower))
    return lang === 'he' ? 'אני מעולה! 🚀 איך אני יכול לסייע?' : 'I\'m great! 🚀 How can I assist?';
  if (/(thank|thanks|תודה|شكرا|gracias|merci|danke|спасибо|谢谢|ありがとう|धन्यवाद)/i.test(lower))
    return lang === 'he' ? 'בשמחה! 🤝' : 'You\'re welcome! 🤝';
  if (/(bye|goodbye|ביי|وداعا|adiós|au revoir|auf wiedersehen|до свидания|再见|さようなら|अलविदा)/i.test(lower))
    return lang === 'he' ? 'ביי! 👋' : 'Bye! 👋';
  return null;
};

// ==================== GOOGLE SEARCH FUNCTION ====================
async function googleSearch(query) {
  if (!GOOGLE_API_KEY || GOOGLE_API_KEY === 'YOUR_GOOGLE_API_KEY' || !GOOGLE_CX) {
    console.warn('⚠️ Google Search not configured. Please set API key and CX.');
    return null;
  }
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 8000);
    const url = `${GOOGLE_SEARCH_URL}?key=${GOOGLE_API_KEY}&cx=${GOOGLE_CX}&q=${encodeURIComponent(query)}&num=3`;
    const response = await fetch(url, { signal: controller.signal });
    clearTimeout(timeoutId);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();
    if (data.items && data.items.length) {
      return data.items.map(item => ({
        title: item.title,
        snippet: item.snippet,
        link: item.link
      }));
    }
    return null;
  } catch (err) {
    console.error('Google search error:', err);
    return null;
  }
}

// ==================== ACTIONS (API CALLS) ====================
// פונקציות לפעולות אמיתיות במערכת – יש להתאים ל-API של השרת שלך
const blockIp = async (ip, reason = 'Suspicious activity detected by Copilot') => {
  const token = localStorage.getItem('accessToken');
  if (!token) return { success: false, error: 'No authentication token' };
  try {
    const response = await fetch('/api/network/block', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ ip, reason })
    });
    return await response.json();
  } catch (err) {
    return { success: false, error: err.message };
  }
};

const sendAlertToAtc = async (message, severity = 'high') => {
  const token = localStorage.getItem('accessToken');
  if (!token) return { success: false, error: 'No authentication token' };
  try {
    const response = await fetch('/api/atc/alert', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ message, severity })
    });
    return await response.json();
  } catch (err) {
    return { success: false, error: err.message };
  }
};

const executeEmergencyProcedure = async (procedureName) => {
  const token = localStorage.getItem('accessToken');
  if (!token) return { success: false, error: 'No authentication token' };
  try {
    const response = await fetch('/api/procedures/execute', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ procedure: procedureName })
    });
    return await response.json();
  } catch (err) {
    return { success: false, error: err.message };
  }
};

// ==================== MAIN COPILOT COMPONENT ====================
const CopilotChat = ({ onNavigate, onFilterAssets, onSelectAsset, onAcknowledgeAlert, onIsolateAsset }) => {
  const [open, setOpen] = useState(false);
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [ollamaStatus, setOllamaStatus] = useState('checking');
  const [useRAGOnly, setUseRAGOnly] = useState(true);
  const [suggestions, setSuggestions] = useState([]);
  const [currentLang, setCurrentLang] = useState('he');
  const messagesEndRef = useRef(null);
  const inputRef = useRef(null);
  const [conversationHistory, setConversationHistory] = useState([]);

  const quickSuggestions = [
    { text: '🔍 מה זה ADS-B spoofing?', lang: 'he' },
    { text: '✈️ מידע על 4XELD', lang: 'he' },
    { text: '🛡️ איך מטפלים ב-Ransomware?', lang: 'he' },
    { text: '📋 נוהל חירום', lang: 'he' },
    { text: '🗺️ עבור למפה', lang: 'he' },
    { text: '🚫 חסום IP 192.168.1.100', lang: 'he' },
    { text: '📡 שלח התרעה ל-ATC: חשד לחטיפה', lang: 'he' },
    { text: '🌍 חפש: בואינג 787 בעיות', lang: 'he' }
  ];

  useEffect(() => {
    const checkOllama = async () => {
      try {
        const res = await fetch('http://localhost:11434/api/tags');
        setOllamaStatus(res.ok ? 'ready' : 'offline');
      } catch { setOllamaStatus('offline'); }
    };
    checkOllama();
    const interval = setInterval(checkOllama, 30000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (messages.length === 0) {
      const greetings = TRANSLATIONS.greetings.he;
      const randomGreeting = greetings[Math.floor(Math.random() * greetings.length)];
      setMessages([{
        id: uniqueId(),
        role: 'ai',
        text: `✨ **Shadow Copilot Ultimate** מופעל!\n\n${randomGreeting}\n\n📚 **יכולות חדשות:**\n• 🚫 חסימת IP – "חסום IP 1.2.3.4"\n• 📡 שליחת התרעה ל-ATC – "שלח התרעה ל-ATC: טקסט"\n• ⚡ ביצוע נוהל חירום – "בצע נוהל חירום"\n• 🧭 ניווט חכם (מפה, מטוסים, איומים, התראות)\n• 🔍 מידע על איומים, מטוסים, נהלים (RAG)\n• 🌐 חיפוש בגוגל – "חפש: מילות מפתח"\n• ${ollamaStatus === 'ready' ? '🧠 AI+RAG (Ollama)' : '📚 RAG Only (מהיר)'}\n• 10 שפות\n\n💡 **דוגמאות:**\n• "עבור למפה"\n• "מה זה ADS-B spoofing?"\n• "פרטי 4XELD"\n• "חסום IP 192.168.1.100"\n• "שלח התרעה ל-ATC: חשד לחטיפה"\n• "בצע נוהל חירום"`,
        timestamp: Date.now()
      }]);
    }
  }, [ollamaStatus]);

  useEffect(() => {
    if (input.length > 2) {
      const matches = searchKnowledge(input);
      setSuggestions(matches.slice(0, 3));
    } else {
      setSuggestions([]);
    }
  }, [input]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  useEffect(() => {
    if (open) setTimeout(() => inputRef.current?.focus(), 100);
  }, [open]);

  useEffect(() => {
    const lastUserMsg = [...messages].reverse().find(m => m.role === 'user');
    if (lastUserMsg) setCurrentLang(detectLanguage(lastUserMsg.text));
  }, [messages]);

  const send = async () => {
    if (!input.trim() || loading) return;
    const userMsg = input.trim();
    const lang = detectLanguage(userMsg);
    const userMessage = { id: uniqueId(), role: 'user', text: userMsg, timestamp: Date.now() };
    setMessages(prev => [...prev, userMessage]);
    setConversationHistory(prev => [...prev, userMessage]);
    setInput('');
    setLoading(true);

    const lower = userMsg.toLowerCase();

    // 1. פקודת ניווט
    const targetPage = detectNavigation(userMsg, lang);
    if (targetPage && onNavigate) {
      onNavigate(targetPage);
      const emoji = { dashboard: '📊', map: '🗺️', assets: '✈️', threats: '🛡️', alerts: '🔔', reports: '📄', audit: '📜' }[targetPage] || '📍';
      const nameHe = { dashboard: 'לדשבורד', map: 'למפה', assets: 'למטוסים', threats: 'לאיומים', alerts: 'להתראות', reports: 'לדוחות', audit: 'לביקורת' }[targetPage] || '';
      const response = lang === 'he' ? `${emoji} מעביר ${nameHe}...` : `${emoji} Navigating to ${targetPage}...`;
      setMessages(prev => [...prev, { id: uniqueId(), role: 'ai', text: response, timestamp: Date.now() }]);
      setLoading(false);
      return;
    }

    // 2. חיפוש ICAO (פרטי מטוס)
    const icaoMatch = userMsg.match(/4X[A-Z0-9]{3}|ISR[A-Z0-9]{3}|ARZ[A-Z0-9]{3}/i);
    if (icaoMatch) {
      const icao = icaoMatch[0].toLowerCase();
      const asset = KNOWLEDGE_BASE.assets[icao];
      if (asset && onSelectAsset && onNavigate) {
        onSelectAsset({ icao24: icao.toUpperCase(), name: asset.type });
        onNavigate('assets');
        const text = lang === 'he' ? `✈️ מצאתי את ${asset.type} (${icao.toUpperCase()}). מעביר לפרטים...` : `✈️ Found ${asset.type} (${icao.toUpperCase()}). Showing details...`;
        setMessages(prev => [...prev, { id: uniqueId(), role: 'ai', text, timestamp: Date.now() }]);
        setLoading(false);
        return;
      }
    }

    // 3. אישור התראה
    if (lower.includes('אשר התראה') || lower.includes('acknowledge alert')) {
      if (onAcknowledgeAlert) await onAcknowledgeAlert();
      setMessages(prev => [...prev, { id: uniqueId(), role: 'ai', text: '✅ ' + (lang === 'he' ? 'אישרתי את ההתראה.' : 'Alert acknowledged.'), timestamp: Date.now() }]);
      setLoading(false);
      return;
    }

    // 4. בידוד מטוס
    if ((lower.includes('בודד') || lower.includes('isolate')) && icaoMatch && onIsolateAsset) {
      const icao = icaoMatch[0].toLowerCase();
      const asset = KNOWLEDGE_BASE.assets[icao];
      if (asset) {
        await onIsolateAsset({ icao24: icao.toUpperCase(), name: asset.type });
        setMessages(prev => [...prev, { id: uniqueId(), role: 'ai', text: `🚨 ${asset.type} (${icao.toUpperCase()}) ${lang === 'he' ? 'בודד בהצלחה!' : 'isolated successfully!'}`, timestamp: Date.now() }]);
        setLoading(false);
        return;
      }
    }

    // 5. חסימת IP (פעולה חדשה)
    const blockIpMatch = lower.match(/חסום|block\s+ip\s+(\d+\.\d+\.\d+\.\d+)/i);
    if (blockIpMatch) {
      let ip = blockIpMatch[1];
      if (!ip) {
        const ipExtract = userMsg.match(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/);
        if (ipExtract) ip = ipExtract[0];
      }
      if (ip) {
        const result = await blockIp(ip);
        if (result.success) {
          setMessages(prev => [...prev, { id: uniqueId(), role: 'ai', text: `🚫 ${lang === 'he' ? `חסימת IP ${ip} בוצעה בהצלחה.` : `IP ${ip} blocked successfully.`}`, timestamp: Date.now() }]);
        } else {
          setMessages(prev => [...prev, { id: uniqueId(), role: 'ai', text: `❌ ${lang === 'he' ? `שגיאה בחסימת IP: ${result.error}` : `Error blocking IP: ${result.error}`}`, timestamp: Date.now() }]);
        }
        setLoading(false);
        return;
      }
    }

    // 6. שליחת התרעה ל-ATC
    if (lower.includes('שלח התרעה ל-atc') || lower.includes('send atc alert')) {
      const alertMsg = userMsg.replace(/שלח התרעה ל-atc|send atc alert/gi, '').trim();
      const finalMsg = alertMsg || (lang === 'he' ? 'התרעת Copilot: אירוע אבטחה' : 'Copilot alert: security event');
      const result = await sendAlertToAtc(finalMsg);
      if (result.success) {
        setMessages(prev => [...prev, { id: uniqueId(), role: 'ai', text: `📡 ${lang === 'he' ? 'ההתרעה ל-ATC נשלחה בהצלחה.' : 'ATC alert sent successfully.'}`, timestamp: Date.now() }]);
      } else {
        setMessages(prev => [...prev, { id: uniqueId(), role: 'ai', text: `❌ ${lang === 'he' ? `שגיאה בשליחה: ${result.error}` : `Error sending alert: ${result.error}`}`, timestamp: Date.now() }]);
      }
      setLoading(false);
      return;
    }

    // 7. ביצוע נוהל חירום
    if (lower.includes('בצע נוהל חירום') || lower.includes('execute emergency procedure')) {
      const result = await executeEmergencyProcedure('emergency');
      if (result.success) {
        setMessages(prev => [...prev, { id: uniqueId(), role: 'ai', text: `⚡ ${lang === 'he' ? 'נוהל חירום הופעל בהצלחה.' : 'Emergency procedure executed successfully.'}`, timestamp: Date.now() }]);
      } else {
        setMessages(prev => [...prev, { id: uniqueId(), role: 'ai', text: `❌ ${lang === 'he' ? `שגיאה בהפעלת הנוהל: ${result.error}` : `Error executing procedure: ${result.error}`}`, timestamp: Date.now() }]);
      }
      setLoading(false);
      return;
    }

    // 8. חיפוש בגוגל
    if (lower.includes('חפש') || lower.includes('search') || lower.includes('google')) {
      let searchQuery = userMsg.replace(/חפש|search|google/gi, '').trim();
      if (!searchQuery) searchQuery = userMsg;
      setMessages(prev => [...prev, { id: uniqueId(), role: 'ai', text: `🔍 ${lang === 'he' ? 'מחפש בגוגל...' : 'Searching Google...'}`, timestamp: Date.now() }]);
      const results = await googleSearch(searchQuery);
      if (results && results.length) {
        let response = `🌐 **${lang === 'he' ? 'תוצאות חיפוש' : 'Search results'}**\n\n`;
        results.slice(0, 3).forEach((res, idx) => {
          response += `${idx+1}. **${res.title}**\n   ${res.snippet?.substring(0, 200) || ''}\n   🔗 ${res.link}\n\n`;
        });
        setMessages(prev => [...prev, { id: uniqueId(), role: 'ai', text: response, timestamp: Date.now() }]);
      } else {
        setMessages(prev => [...prev, { id: uniqueId(), role: 'ai', text: `❌ ${lang === 'he' ? 'לא נמצאו תוצאות. נסה שאילתה אחרת.' : 'No results. Try a different query.'}`, timestamp: Date.now() }]);
      }
      setLoading(false);
      return;
    }

    // 9. RAG + Quick Response
    const ragResults = searchKnowledge(userMsg);
    const quickResp = getQuickResponse(userMsg, lang);
    if (quickResp) {
      setMessages(prev => [...prev, { id: uniqueId(), role: 'ai', text: quickResp, timestamp: Date.now() }]);
      setLoading(false);
      return;
    }

    if (ragResults.length > 0 && useRAGOnly) {
      let response = '';
      for (const r of ragResults.slice(0, 2)) {
        if (r.type === 'threat') response += `**${r.title}**\n📝 ${r.description}\n🛡️ טיפול: ${r.mitigation}\n🔧 תיקון: ${r.remediation}\n\n`;
        else if (r.type === 'asset') response += `**${r.key.toUpperCase()}**\n✈️ סוג: ${r.type}\n🏢 חברה: ${r.airline}\n📅 שנה: ${r.year}\n\n`;
        else if (r.type === 'procedure') response += `${r.content}\n\n`;
        else if (r.type === 'regulation') response += `📜 ${r.content}\n\n`;
      }
      setMessages(prev => [...prev, { id: uniqueId(), role: 'ai', text: response || (lang === 'he' ? 'לא מצאתי מידע רלוונטי.' : 'No info found.'), timestamp: Date.now() }]);
      setLoading(false);
      return;
    }

    if (ragResults.length > 0 && ollamaStatus === 'ready') {
      const ragContext = ragResults.map(r => {
        if (r.type === 'threat') return `Threat: ${r.title} - ${r.description} - Mitigation: ${r.mitigation}`;
        if (r.type === 'asset') return `Aircraft: ${r.key} - ${r.type} - ${r.airline}`;
        return '';
      }).join('\n');
      const historyContext = conversationHistory.slice(-3).map(m => `${m.role}: ${m.text.substring(0, 100)}`).join('\n');
      const prompt = `You are Shadow Copilot. Answer in ${LANGUAGES[lang]?.name || 'English'}. Keep response short (2-3 sentences). Use RAG if relevant.\nHistory:\n${historyContext}\nRAG:\n${ragContext}\nUser: ${userMsg}\nAssistant:`;
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 25000);
        const response = await fetch('http://localhost:11434/api/generate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          signal: controller.signal,
          body: JSON.stringify({ model: 'mistral:7b', prompt, stream: false, options: { temperature: 0.7, num_predict: 150 } })
        });
        clearTimeout(timeoutId);
        if (response.ok) {
          const data = await response.json();
          setMessages(prev => [...prev, { id: uniqueId(), role: 'ai', text: data.response || (lang === 'he' ? 'לא הצלחתי לענות.' : 'Could not answer.'), timestamp: Date.now() }]);
          setLoading(false);
          return;
        }
      } catch (err) { console.error('Ollama error:', err); }
    }

    // Fallback
    const fallbackMsg = TRANSLATIONS.fallbackMessages[lang] || TRANSLATIONS.fallbackMessages.en;
    setMessages(prev => [...prev, { id: uniqueId(), role: 'ai', text: fallbackMsg, timestamp: Date.now() }]);
    setLoading(false);
  };

  return (
    <>
      <motion.button
        onClick={() => setOpen(true)}
        className="fixed z-[9999] w-12 h-12 rounded-full shadow-lg flex items-center justify-center transition-all hover:scale-105 group"
        style={{ bottom: '20px', right: '20px', background: 'linear-gradient(135deg, #00d9f7, #8b5cf6)' }}
        whileHover={{ scale: 1.05 }}
        whileTap={{ scale: 0.95 }}
      >
        <i className="fas fa-robot text-white text-lg" />
        {ollamaStatus === 'ready' && <span className="absolute -top-1 -right-1 w-3 h-3 bg-green-500 rounded-full animate-pulse" />}
      </motion.button>

      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ opacity: 0, scale: 0.9, y: 20 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.9, y: 20 }}
            className="fixed z-[9999] w-[460px] rounded-xl shadow-2xl flex flex-col overflow-hidden backdrop-blur-sm"
            style={{ bottom: '90px', right: '20px', background: 'rgba(8, 12, 26, 0.95)', border: '1px solid rgba(0,217,247,0.4)', backdropFilter: 'blur(10px)' }}
          >
            <div className="flex items-center justify-between px-4 py-3 border-b" style={{ borderColor: 'rgba(0,217,247,0.2)' }}>
              <div className="flex items-center gap-2">
                <div className="w-8 h-8 rounded-full flex items-center justify-center" style={{ background: 'linear-gradient(135deg, #00d9f7, #8b5cf6)' }}>
                  <i className="fas fa-robot text-white text-xs" />
                </div>
                <div>
                  <span className="text-sm font-semibold text-gradient">Shadow Copilot Ultimate</span>
                  <div className="flex items-center gap-1 text-[9px]">
                    <div className={`w-1.5 h-1.5 rounded-full ${ollamaStatus === 'ready' ? 'bg-green-500' : 'bg-red-500'}`} />
                    <span className="text-gray-400">{ollamaStatus === 'ready' ? 'AI Ready' : 'RAG Mode'}</span>
                    <span className="text-gray-600 mx-1">•</span>
                    <button onClick={() => setUseRAGOnly(!useRAGOnly)} className="hover:text-s-accent transition-colors text-gray-400 text-[9px]">
                      {useRAGOnly ? '📚 RAG Only' : '🧠 AI+RAG'}
                    </button>
                    <span className="text-gray-600 mx-1">•</span>
                    <span className="text-gray-400 text-[9px]">{LANGUAGES[currentLang]?.flag || '🌐'} {LANGUAGES[currentLang]?.name || 'עברית'}</span>
                  </div>
                </div>
              </div>
              <button onClick={() => setOpen(false)} className="text-gray-400 hover:text-white"><i className="fas fa-times" /></button>
            </div>

            <div className="flex-1 overflow-y-auto p-3 space-y-2" style={{ maxHeight: '400px', minHeight: '320px' }}>
              {messages.slice(-20).map((msg) => (
                <motion.div key={msg.id} initial={{ opacity: 0, x: msg.role === 'user' ? 20 : -20 }} animate={{ opacity: 1, x: 0 }} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                  <div className={`max-w-[85%] rounded-2xl px-3 py-2 text-xs whitespace-pre-wrap ${msg.role === 'user' ? 'bg-gradient-to-r from-s-accent/20 to-purple-500/20 text-s-accent' : 'bg-gray-800/50 text-gray-200 border border-gray-700'}`}>
                    {msg.text}
                    <div className="text-[9px] text-gray-500 mt-1">{new Date(msg.timestamp).toLocaleTimeString()}</div>
                  </div>
                </motion.div>
              ))}
              {loading && (
                <div className="flex justify-start">
                  <div className="bg-gray-800/50 rounded-2xl px-3 py-2 text-xs text-gray-400 flex items-center gap-1">
                    <span>🤔</span>
                    <span className="animate-pulse">{currentLang === 'he' ? 'חושב' : 'Thinking'}</span>
                    <span className="w-1 h-1 bg-gray-500 rounded-full animate-bounce" style={{ animationDelay: '0s' }} />
                    <span className="w-1 h-1 bg-gray-500 rounded-full animate-bounce" style={{ animationDelay: '0.2s' }} />
                    <span className="w-1 h-1 bg-gray-500 rounded-full animate-bounce" style={{ animationDelay: '0.4s' }} />
                  </div>
                </div>
              )}
              <div ref={messagesEndRef} />
            </div>

            {suggestions.length > 0 && !loading && (
              <div className="px-3 py-2 border-t border-gray-700/30">
                <div className="text-[9px] text-gray-500 mb-1">💡 {currentLang === 'he' ? 'הצעות' : 'Suggestions'}:</div>
                <div className="flex flex-wrap gap-1">
                  {suggestions.map((s, i) => (
                    <button key={i} onClick={() => setInput(s.type === 'threat' ? `מה זה ${s.key}?` : `פרטי ${s.key}`)} className="text-[9px] px-2 py-0.5 rounded-full bg-gray-700/50 text-gray-300 hover:bg-s-accent/20">
                      {s.type === 'threat' ? `🛡️ ${s.key}` : s.type === 'asset' ? `✈️ ${s.key}` : `📋 ${s.key}`}
                    </button>
                  ))}
                </div>
              </div>
            )}

            <div className="px-3 py-2 border-t border-gray-700/30">
              <div className="flex flex-wrap gap-1">
                {quickSuggestions.map((s, i) => (
                  <button key={i} onClick={() => setInput(s.text.replace(/^[^\w]+/, ''))} className="text-[9px] px-2 py-0.5 rounded-full bg-gray-800/50 text-gray-400 hover:text-s-accent">
                    {s.text}
                  </button>
                ))}
              </div>
            </div>

            <div className="p-3 border-t border-gray-700/30">
              <div className="flex gap-2">
                <input ref={inputRef} value={input} onChange={e => setInput(e.target.value)} onKeyDown={e => e.key === 'Enter' && send()} placeholder={currentLang === 'he' ? 'פקודות: ניווט, חסום IP, שלח התרעה ל-ATC, נוהל חירום, חיפוש...' : 'Commands: navigate, block IP, send ATC alert, emergency procedure, search...'} className="flex-1 bg-gray-900/50 border border-gray-700 rounded-xl px-3 py-2 text-sm text-white outline-none focus:border-s-accent/50" disabled={loading} />
                <button onClick={send} disabled={loading || !input.trim()} className="px-3 py-2 rounded-xl bg-gradient-to-r from-s-accent to-purple-500 text-white text-sm disabled:opacity-50 transition-all hover:scale-105">
                  <i className="fas fa-paper-plane" />
                </button>
              </div>
              <div className="text-[8px] text-center text-gray-600 mt-2">
                {useRAGOnly ? '📚 RAG Mode (מהיר)' : '🧠 AI+RAG Mode (חכם יותר)'} | 🚫 "חסום IP 1.2.3.4" | 📡 "שלח התרעה ל-ATC" | ⚡ "בצע נוהל חירום"
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  );
};

export default CopilotChat;