#!/bin/bash

set -e

terser app.js -c -o app.js
#terser style.css -c -o style.css
html-minifier-terser --collapse-whitespace index.html -o index.html
