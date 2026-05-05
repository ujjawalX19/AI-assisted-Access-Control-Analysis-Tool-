FROM node:20-slim

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .

EXPOSE 5173

# We use --host 0.0.0.0 to ensure the dev server is accessible outside the container
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]
