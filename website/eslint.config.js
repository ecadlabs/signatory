module.exports = [
  {
    ignores: ['build/**', 'node_modules/**'],
  },
  {
    files: ['**/*.{js,jsx,mjs,cjs,ts,tsx}'],
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'module',
      parserOptions: {
        ecmaFeatures: {
          jsx: true,
        },
      },
    },
    rules: {
      // Basic rules
      'no-console': 'warn',
      'no-unused-vars': 'warn',
      'prefer-const': 'warn',
    },
  },
]; 