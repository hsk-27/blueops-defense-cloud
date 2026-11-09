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
        soc: {
          canvas: '#090a0f',    // Deep Carbon Obsidian Canvas
          surface: '#11141d',   // Elevated Titanium Charcoal
          card: '#141824',      // Card Container
          header: '#171b26',    // Toolbars & Sub-headers
          border: '#212738',    // 1px Hair-line Border
          hover: '#1c2232',     // Table row / Nav hover
          accent: '#e11d48',    // Falcon Action Crimson
          cobalt: '#0284c7',    // Diagnostic Steel Cobalt
          indigo: '#4f46e5',    // Tactical Indigo Brand Accent
          muted: '#8492a6',     // Industrial Cool Gray Text
          light: '#f8fafc',     // Off-white Primary Text
        }
      }
    },
  },
  plugins: [],
}
