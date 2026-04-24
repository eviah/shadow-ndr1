export default {
  content: ['./index.html','./src/**/*.{js,jsx}'],
  theme: { extend: {
    fontFamily: {
      display: ['"Syne"','sans-serif'],
      mono:    ['"Share Tech Mono"','monospace'],
      body:    ['"DM Sans"','system-ui'],
    },
    colors: {
      s: {
        void:'#0a0a0b', deep:'#101012', panel:'#161618',
        border:'#27272a', accent:'#d97706', warn:'#d97706',
        danger:'#b91c1c', ok:'#059669', purple:'#52525b', gold:'#ca8a04',
      }
    },
    animation: {
      'scan': 'scan 4s linear infinite',
      'pulse-slow': 'pulse 3s ease-in-out infinite',
      'slide-up': 'slideUp 0.35s ease-out',
    },
    keyframes: {
      scan:    {'0%':{transform:'translateY(-100%)'},'100%':{transform:'translateY(100%)'}},
      slideUp: {'0%':{opacity:0,transform:'translateY(12px)'},'100%':{opacity:1,transform:'translateY(0)'}},
    },
  }},
  plugins: [],
}
