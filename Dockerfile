# Net-Pulse container image. Built for the public read-only demo (see
# render.yaml), but `docker run` works anywhere:
#
#   docker build -t netpulse .
#   docker run --rm -p 8080:8080 netpulse                 # demo mode
#
# Inside a container the agent monitors the container's host, not your PC.
# To monitor your own machine, run the binary from a GitHub Release instead.

# 1. Dashboard
FROM node:22-alpine AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

# 2. Agent, with the dashboard embedded. SQLite is pure Go, so no cgo.
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /src/web/dist ./web/dist
ARG VERSION=docker
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/netpulse ./cmd/netpulse

# 3. Runtime: no shell, no package manager, CA certificates for TLS checks,
# runs as an unprivileged user.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/netpulse /netpulse
COPY deploy/demo-config.json /etc/netpulse/demo-config.json
ENV PORT=8080
EXPOSE 8080
ENTRYPOINT ["/netpulse"]
CMD ["serve", "-demo", "-config", "/etc/netpulse/demo-config.json", "-data-dir", "/tmp/netpulse"]
