/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx,ts,tsx,vue}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: { brand: { 50: '#eef6ff', 500: '#2b7fff', 900: '#0b2f6b' } },
      fontFamily: { sans: ['Inter', 'system-ui', 'sans-serif'] },
      keyframes: { fade: { '0%': { opacity: 0 }, '100%': { opacity: 1 } } },
      animation: { fade: 'fade 200ms ease-out both' },
    },
  },
  plugins: [],
}
