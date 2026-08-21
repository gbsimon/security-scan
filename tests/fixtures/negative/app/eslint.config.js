import js from '@eslint/js'
import react from 'eslint-plugin-react'

export default [
  js.configs.recommended,
  {
    files: ['**/*.{js,jsx}'],
    languageOptions: { ecmaVersion: 2022, sourceType: 'module' },
    plugins: { react },
    rules: { 'no-unused-vars': 'warn', 'react/jsx-uses-react': 'off' },
  },
]
