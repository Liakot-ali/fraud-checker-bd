'use strict';

/** @type {import('tailwindcss').Config} */
module.exports = {
    // Scan the HTML (including the class names inside inline <script> templates)
    // and any client JS so every utility used at runtime is generated.
    content: ['./public/**/*.html', './public/**/*.js'],
    theme: { extend: {} },
    plugins: []
};
