/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      // SRS 24: a restrained forensic palette. The greens and pinks are signal
      // colours, not decoration — green only marks verified outcomes.
      colors: {
        canvas: "#070B12",
        panel: "#0C121C",
        edge: "#1B2533",
        hhg: "#0B6839",
        signal: "#B7FF4A",
        policy: "#FEE101",
        accent: "#FF0080",
        exploit: "#FF5B6E",
        evidence: "#B79CFF",
        ink: "#FFFBE8",
        muted: "#8A97A8",
      },
      fontFamily: {
        mono: ["ui-monospace", "SFMono-Regular", "Menlo", "monospace"],
      },
      keyframes: {
        slidein: {
          from: { opacity: "0", transform: "translateY(-4px)" },
          to: { opacity: "1", transform: "translateY(0)" },
        },
        pulseglow: {
          "0%, 100%": { opacity: "1" },
          "50%": { opacity: "0.45" },
        },
      },
      animation: {
        slidein: "slidein 220ms ease-out",
        pulseglow: "pulseglow 1.6s ease-in-out infinite",
      },
    },
  },
  plugins: [],
};
