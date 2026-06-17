#!/bin/bash

echo "[+] Killing any existing Hexo server on port 4000..."
fuser -k 4000/tcp 2>/dev/null
sleep 1

echo "[+] Starting Hexo server..."
npx hexo server --port 4000
