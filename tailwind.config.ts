import type { Config } from "tailwindcss";
import tailwindcssAnimate from "tailwindcss-animate";

const token = (name: string) => `hsl(var(--${name}) / <alpha-value>)`;

const config: Config = {
  darkMode: ["class"],
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}", "./lib/**/*.{ts,tsx}"],
  theme: {
    extend: {
      // Desktop monitors: 3xl is where a 1920px screen gets side-by-side panels and right rails.
      screens: { "3xl": "1800px" },
      maxWidth: { content: "1760px" },
      fontFamily: {
        // System stacks only: nothing is downloaded at build or run time, so CI stays offline.
        sans: ['"Segoe UI Variable Text"', '"Segoe UI"', "Inter", "ui-sans-serif", "system-ui", "-apple-system", "Roboto", '"Helvetica Neue"', "Arial", "sans-serif"],
        mono: ['"Cascadia Code"', '"JetBrains Mono"', "ui-monospace", "SFMono-Regular", "Menlo", "Consolas", "monospace"],
      },
      borderRadius: {
        xl: "calc(var(--radius) + 4px)",
        lg: "var(--radius)",
        md: "calc(var(--radius) - 2px)",
        sm: "calc(var(--radius) - 4px)",
      },
      colors: {
        background: token("background"),
        foreground: token("foreground"),
        card: { DEFAULT: token("card"), foreground: token("card-foreground") },
        popover: { DEFAULT: token("popover"), foreground: token("popover-foreground") },
        primary: { DEFAULT: token("primary"), foreground: token("primary-foreground") },
        secondary: { DEFAULT: token("secondary"), foreground: token("secondary-foreground") },
        muted: { DEFAULT: token("muted"), foreground: token("muted-foreground") },
        accent: { DEFAULT: token("accent"), foreground: token("accent-foreground") },
        destructive: { DEFAULT: token("destructive"), foreground: token("destructive-foreground") },
        success: { DEFAULT: token("success"), foreground: token("success-foreground") },
        warning: { DEFAULT: token("warning"), foreground: token("warning-foreground") },
        info: { DEFAULT: token("info"), foreground: token("info-foreground") },
        classical: token("classical"),
        pq: token("pq"),
        hybrid: token("hybrid"),
        sidebar: { DEFAULT: token("sidebar"), foreground: token("sidebar-foreground"), border: token("sidebar-border") },
        border: token("border"),
        input: token("input"),
        ring: token("ring"),
      },
      boxShadow: {
        card: "0 1px 2px 0 rgb(15 23 42 / 0.04), 0 1px 3px 0 rgb(15 23 42 / 0.03)",
        elevated: "0 10px 30px -12px rgb(15 23 42 / 0.25), 0 2px 6px -2px rgb(15 23 42 / 0.08)",
      },
      keyframes: {
        "accordion-down": {
          from: { height: "0" },
          to: { height: "var(--radix-accordion-content-height)" },
        },
        "accordion-up": {
          from: { height: "var(--radix-accordion-content-height)" },
          to: { height: "0" },
        },
        "fade-in": { from: { opacity: "0" }, to: { opacity: "1" } },
        "slide-up": { from: { opacity: "0", transform: "translateY(6px)" }, to: { opacity: "1", transform: "translateY(0)" } },
        "scale-in": { from: { opacity: "0", transform: "scale(0.97)" }, to: { opacity: "1", transform: "scale(1)" } },
      },
      animation: {
        "accordion-down": "accordion-down 0.2s ease-out",
        "accordion-up": "accordion-up 0.2s ease-out",
        "fade-in": "fade-in 0.2s ease-out",
        "slide-up": "slide-up 0.25s cubic-bezier(0.16, 1, 0.3, 1)",
        "scale-in": "scale-in 0.18s cubic-bezier(0.16, 1, 0.3, 1)",
      },
    },
  },
  // Imported, not require()d: this file is loaded as an ES module, where require is
  // undefined on Node 24.
  plugins: [tailwindcssAnimate],
};

export default config;
