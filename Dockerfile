# Stage 1: build the frontend
FROM node:24-alpine AS web
WORKDIR /app/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

# Stage 2: build the Go binary (the OpenAPI spec and Scalar bundle in api/
# are embedded via go:embed, so they must be in the build context)
FROM golang:1.26-alpine AS build
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /linkcheck ./cmd/linkcheck

# Stage 3: minimal runtime. distroless/static has no shell and no libc —
# exactly enough to run a static binary as a non-root user.
FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=build /linkcheck /app/linkcheck
COPY --from=web /app/web/dist /app/web/dist
EXPOSE 8080
ENTRYPOINT ["/app/linkcheck"]
