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
        void:'#030610', deep:'#07091a', panel:'#0b0f22',
        border:'#15203a', accent:'#00d9f7', warn:'#ff7b00',
        danger:'#ff1f4c', ok:'#00e87a', purple:'#8b5cf6', gold:'#fbbf24',
        
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
