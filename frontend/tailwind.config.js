/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        navy: {
          950: '#07111f',
          900: '#0b1728',
          800: '#12243d',
        },
        primary: {
          500: '#2563eb',
          600: '#1d4ed8',
        },
        success: '#16a34a',
        warning: '#d97706',
        danger: '#dc2626',
        slate: {
          950: '#0f172a',
        },
      },
      boxShadow: {
        soft: '0 8px 24px rgba(15, 23, 42, 0.08)',
      },
    },
  },
  plugins: [],
};
