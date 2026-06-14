# syntax=docker/dockerfile:1

# ---- build/prepare stage ----
# (No dependencies to install, but this stage keeps the final image clean and
#  gives you a place to add a build step later.)
FROM node:20-slim AS build
WORKDIR /app
COPY package.json ./
# If you add dependencies later: COPY package-lock.json ./ && npm ci --omit=dev
COPY server.js ./
COPY public ./public

# ---- runtime stage: distroless, non-root, minimal attack surface ----
FROM gcr.io/distroless/nodejs20-debian12:nonroot
WORKDIR /app
COPY --from=build /app /app

# distroless 'nonroot' already runs as uid 65532
USER nonroot
EXPOSE 8080
ENV NODE_ENV=production PORT=8080
CMD ["server.js"]
