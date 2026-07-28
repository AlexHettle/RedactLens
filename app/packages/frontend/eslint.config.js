import js from '@eslint/js'
import globals from 'globals'
import reactHooks from 'eslint-plugin-react-hooks'
import reactRefresh from 'eslint-plugin-react-refresh'
import jsxA11y from 'eslint-plugin-jsx-a11y'
import tseslint from 'typescript-eslint'
import prettier from 'eslint-config-prettier'

export default tseslint.config(
  { ignores: ['dist'] },
  {
    extends: [
      js.configs.recommended,
      ...tseslint.configs.recommended,
      // reactHooks.configs['recommended-latest'] ships a malformed flat
      // config (plugins as a string array) on this version; rebuild it
      // from the plugin object + its rules instead of spreading the preset.
      {
        plugins: { 'react-hooks': reactHooks },
        rules: reactHooks.configs['recommended-latest'].rules,
      },
      reactRefresh.configs.vite,
      jsxA11y.flatConfigs.recommended,
      prettier,
    ],
    files: ['**/*.{ts,tsx}'],
    languageOptions: {
      ecmaVersion: 2020,
      globals: globals.browser,
    },
  },
)
