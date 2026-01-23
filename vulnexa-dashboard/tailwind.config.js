/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: "class",
  theme: {
    extend: {
      fontFamily: {
        mono: ["JetBrains Mono", "Fira Code", "ui-monospace", "SFMono-Regular", "Menlo", "monospace"]
      },
      colors: {
        cyber: {
          bg: "#050509",
          card: "#0f172a",
          border: "#94a3b8",
          red: "#ff3366",
          cyan: "#22e3ff",
          purple: "#b158ff"
        }
      },
      boxShadow: {
        "neon-red": "0 0 20px rgba(255, 51, 102, 0.7)",
        "neon-cyan": "0 0 18px rgba(34, 227, 255, 0.65)",
        "neon-purple": "0 0 20px rgba(177, 88, 255, 0.6)",
        "glass-soft": "0 18px 45px rgba(15,23,42,0.8)"
      },
      animation: {
        "pulse-soft": "pulse-soft 2s infinite",
        "scan-line": "scan-line 2s linear infinite",
        "matrix-fall": "matrix-fall 10s linear infinite",
        "glow": "glow 2s ease-in-out infinite alternate",
        "rotate-border": "rotate-border 4s linear infinite",
        "progress": "progress 1.5s ease-in-out"
      },
      keyframes: {
        "pulse-soft": {
          "0%, 100%": { opacity: 0.4 },
          "50%": { opacity: 1 }
        },
        "scan-line": {
          "0%": { transform: "translateX(-100%)" },
          "100%": { transform: "translateX(100%)" }
        },
        "matrix-fall": {
          "0%": { transform: "translateY(-100%)" },
          "100%": { transform: "translateY(100%)" }
        },
        "glow": {
          "0%": { boxShadow: "0 0 5px rgba(34, 227, 255, 0.5)" },
          "100%": { boxShadow: "0 0 25px rgba(34, 227, 255, 0.8)" }
        },
        "rotate-border": {
          "0%": { transform: "rotate(0deg)" },
          "100%": { transform: "rotate(360deg)" }
        },
        "progress": {
          "0%": { width: "0%" },
          "100%": { width: "100%" }
        }
      }
    }
  },
  plugins: []
}