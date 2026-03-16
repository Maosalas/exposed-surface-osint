# ── OSINT Puppeteer Screenshot Service ────────────────────────────────────────
FROM ghcr.io/puppeteer/puppeteer:21.6.1

LABEL description="OSINT screenshot service - internal only"

WORKDIR /home/pptruser/app

COPY package.json ./

# Install puppeteer (full, includes Chrome download)
# PUPPETEER_CACHE_DIR is set by the official image to /home/pptruser/.cache/puppeteer
RUN npm install --omit=dev

COPY server.js ./

USER pptruser

EXPOSE 3000

HEALTHCHECK --interval=20s --timeout=10s --start-period=45s --retries=3 \
    CMD node -e "require('http').get('http://localhost:3000/health',r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))"

CMD ["node", "server.js"]
