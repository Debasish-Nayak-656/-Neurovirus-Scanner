# Stage 1: build React app
FROM node:18-alpine AS build

WORKDIR /app

ENV NODE_OPTIONS=--max_old_space_size=2048
ENV CI=false
ENV GENERATE_SOURCEMAP=false
ENV REACT_APP_API_URL=http://backend:5000

COPY package.json ./

# Install deps, then force fix the ajv conflict
RUN npm install --legacy-peer-deps && \
    npm install ajv@^8.0.0 --legacy-peer-deps

COPY public ./public
COPY src ./src
COPY .env ./

RUN npm run build

# Stage 2: serve with nginx
FROM nginx:alpine
COPY --from=build /app/build /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
