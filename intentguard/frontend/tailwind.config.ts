import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        canvas: {
          DEFAULT: "#FAF9F6",
          alt: "#F2F0EA",
        },
        surface: {
          DEFAULT: "#FFFFFF",
          elevated: "#FAFAF9",
        },
        charcoal: {
          DEFAULT: "#1C1917",
          muted: "#57534E",
          subtle: "#78716C",
        },
        stone: {
          border: "#E5E4DF",
          divider: "#F5F5F4",
        },
      },
      fontFamily: {
        sans: ["Inter", "-apple-system", "BlinkMacSystemFont", "Segoe UI", "sans-serif"],
        mono: ["JetBrains Mono", "Geist Mono", "monospace"],
      },
    },
  },
  plugins: [],
};
export default config;
