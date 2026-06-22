'use strict';

const js = require('@eslint/js');
const globals = require('globals');

module.exports = [
    { ignores: ['node_modules/**', 'public/tailwind.css'] },
    js.configs.recommended,
    {
        // Server-side / tooling (CommonJS, Node globals)
        files: ['**/*.js'],
        languageOptions: {
            ecmaVersion: 2022,
            sourceType: 'commonjs',
            globals: { ...globals.node }
        },
        rules: {
            'no-empty': ['error', { allowEmptyCatch: true }],
            'no-unused-vars': ['warn', { argsIgnorePattern: '^_', caughtErrors: 'none' }],
            'no-useless-escape': 'off'
        }
    },
    {
        // Browser scripts served to the client
        files: ['public/**/*.js'],
        languageOptions: {
            ecmaVersion: 2022,
            sourceType: 'script',
            globals: { ...globals.browser }
        },
        rules: {
            'no-unused-vars': ['warn', { caughtErrors: 'none' }]
        }
    }
];
