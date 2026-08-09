# Build binpassd as a static, CGO-free binary and ship it on a minimal image.
FROM golang:1.26-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

ARG VERSION=dev
ARG COMMIT=none
ARG BUILD_DATE=unknown
ENV CGO_ENABLED=0
RUN go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${BUILD_DATE}" \
      -o /out/binpassd ./cmd/binpassd

FROM alpine:3.20
RUN adduser -D -u 10001 binpass \
 && mkdir -p /var/lib/binpassd/blobs \
 && chown -R binpass:binpass /var/lib/binpassd
COPY --from=build /out/binpassd /usr/local/bin/binpassd
COPY config/config.yaml /etc/binpassd/config.yaml
USER binpass
EXPOSE 8080 8081
ENTRYPOINT ["/usr/local/bin/binpassd", "--config", "/etc/binpassd/config.yaml"]
