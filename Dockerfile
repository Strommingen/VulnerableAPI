FROM node:latest

# Set the working directory inside the container
WORKDIR /app

# Copy the package.json and package-lock.json for npm install
COPY package*.json ./

RUN npm install

EXPOSE 3000

COPY . .

CMD ["npm", "start"]
