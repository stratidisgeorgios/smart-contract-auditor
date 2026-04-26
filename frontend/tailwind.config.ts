import type { Config } from 'tailwindcss'

const config: Config = {
  content: [ 
    './src/pages/**/*.{js,ts,jsx,tsx,mdx}',
    './src/components/**/*.{js,ts,jsx,tsx,mdx}',
    './src/app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      fontFamily: {
        display: ['var(--font-oxanium)'],
        mono:    ['var(--font-space-mono)', 'monospace'],
        sans:    ['var(--font-dm-sans)', 'sans-serif'],
      },
      colors: { // Custom colors for the app's dark cyberpunk theme.
        bg: {
          base:    '#080C14', // The very bottom layer —> page background
          surface: '#0D1526', // panels and containers
          card:    '#111D30', // Cards and interactive elements
          border:  '#1C2D45', // dividers and borders
        },
        brand: { // Colors used for gradients and highlights
          cyan:   '#00D4FF',
          purple: '#9B4DFF',
          pink:   '#FF2D7C',
        },
        severity: { // Severity specific colours —> used for vulnerability badges and indicators
          critical: '#EF4444',
          high:     '#F97316',
          medium:   '#EAB308',
          low:      '#3B82F6',
          info:     '#6B7280',
        },
      },
    },
  },
  plugins: [],
}
export default config