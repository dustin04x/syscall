# syntax=docker/dockerfile:1

FROM node:22-alpine AS build
WORKDIR /app

COPY ui/package.json ui/package-lock.json* ./
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi

COPY ui/ ./
RUN npm run build

FROM nginx:1.27-alpine AS runtime
COPY docker/nginx.ui.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
