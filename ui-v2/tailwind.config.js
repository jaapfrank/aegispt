/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        bg: "var(--bg)",
        "bg-2": "var(--bg-2)",
        surface: "var(--surface)",
        "surface-2": "var(--surface-2)",
        border: "var(--border)",
        line: "var(--line)",
        "line-soft": "var(--line-soft)",
        cyan: "var(--cyan)",
        amber: "var(--amber)",
        green: "var(--green)",
        red: "var(--red)",
        violet: "var(--violet)",
        ok: "var(--ok)",
        hi: "var(--hi)",
        med: "var(--med)",
        info: "var(--info)",
        ai: "var(--ai)",
        text: "var(--text)",
        muted: "var(--muted)",
        soft: "var(--soft)",
      },
      fontFamily: {
        sans: ['Inter', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono"', '"IBM Plex Mono"', 'ui-monospace', 'Menlo', 'monospace'],
      },
      borderRadius: {
        sm: "var(--r-sm)",
        DEFAULT: "var(--r)",
        lg: "var(--r-lg)",
        xl: "var(--r-lg)",
        "2xl": "var(--r-lg)",
        "3xl": "var(--r-lg)",
        full: "9999px",
      },
      animation: {
        'shimmer': 'shimmer-slide 2.5s infinite linear',
        'pulse-fast': 'pulse-fast 1.4s ease-in-out infinite',
        'breathe': 'empty-breathe 3s ease-in-out infinite',
        'critical-flash': 'critical-vignette 0.8s ease-out forwards',
        'thread': 'thread-draw 1.2s ease-out forwards',
        'sonar': 'sonar-ring 1.8s ease-out infinite',
        'pulse-travel': 'pulse-travel 1.6s ease-in-out infinite',
        'pop': 'node-pop 0.6s cubic-bezier(0.16, 1, 0.3, 1) forwards',
        'badge': 'badge-pop 0.5s cubic-bezier(0.34, 1.56, 0.64, 1) forwards',
        'finding-hit': 'finding-hit 0.6s cubic-bezier(0.34, 1.56, 0.64, 1) forwards',
      }
    },
  },
  plugins: [],
}