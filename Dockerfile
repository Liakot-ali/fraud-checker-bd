# Fraud-Checker-BD — production image
FROM node:20-alpine

WORKDIR /app

# Install only production deps (the Tailwind CSS is pre-built and committed,
# so devDependencies are not needed at runtime).
COPY package*.json ./
RUN npm ci --omit=dev

COPY . .

ENV NODE_ENV=production
EXPOSE 3000

# Run as the unprivileged user that ships with the node image.
USER node

CMD ["node", "server.js"]
