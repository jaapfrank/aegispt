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
        surface: "var(--surface)",
        border: "var(--border)",
        cyan: "var(--cyan)",
        amber: "var(--amber)",
        green: "var(--green)",
        red: "var(--red)",
        violet: "var(--violet)",
        text: "var(--text)",
        muted: "var(--muted)",
      },
      fontFamily: {
        sans: ['Inter', 'ui-sans-serif', 'system-ui', 'sans-serif'],
      }
    },
  },
  plugins: [],
}