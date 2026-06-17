#!/bin/bash

echo "[+] Cleaning cache..."
npx hexo clean

echo "[+] Deploying to GitHub Pages..."
npx hexo deploy --generate

echo "[+] Done! Your site is live."
