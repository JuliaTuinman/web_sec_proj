FROM node:20-alpine
WORKDIR /usr/src/testbed
COPY package*.json ./
RUN npm install --omit=dev
COPY . .
EXPOSE 3000
CMD ["node", "app/server.js"]
