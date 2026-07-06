/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // SOC dark palette
        'cyber-bg':       '#0a0e1a',
        'cyber-surface':  '#0f1729',
        'cyber-card':     '#141e36',
        'cyber-border':   '#1e2d4a',
        'cyber-blue':     '#3b82f6',
        'cyber-cyan':     '#06b6d4',
        'cyber-green':    '#10b981',
        'cyber-amber':    '#f59e0b',
        'cyber-red':      '#ef4444',
        'cyber-purple':   '#8b5cf6',
        'cyber-text':     '#e2e8f0',
        'cyber-muted':    '#64748b',
      },
      fontFamily: {
        'mono': ['JetBrains Mono', 'Fira Code', 'Consolas', 'monospace'],
        'sans': ['Inter', 'system-ui', 'sans-serif'],
      },
      animation: {
        'pulse-slow':    'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'glow':          'glow 2s ease-in-out infinite alternate',
        'slide-in':      'slideIn 0.3s ease-out',
        'fade-in':       'fadeIn 0.4s ease-out',
        'scan-line':     'scanLine 4s linear infinite',
      },
      keyframes: {
        glow: {
          '0%':   { boxShadow: '0 0 5px #3b82f6, 0 0 10px #3b82f6' },
          '100%': { boxShadow: '0 0 10px #06b6d4, 0 0 25px #06b6d4' },
        },
        slideIn: {
          '0%':   { transform: 'translateY(-10px)', opacity: '0' },
          '100%': { transform: 'translateY(0)',     opacity: '1' },
        },
        fadeIn: {
          '0%':   { opacity: '0' },
          '100%': { opacity: '1' },
        },
        scanLine: {
          '0%':   { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(100vh)' },
        },
      },
      backgroundImage: {
        'grid-pattern': "linear-gradient(rgba(59,130,246,0.05) 1px, transparent 1px), linear-gradient(90deg, rgba(59,130,246,0.05) 1px, transparent 1px)",
      },
      backgroundSize: {
        'grid': '40px 40px',
      },
    },
  },
  plugins: [],
}
