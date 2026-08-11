# Secret Service integration image for binpass.
#
# The unit tests cover the store and the transport crypto in isolation. This
# is where the provider meets a real client: secret-tool from libsecret, which
# is what Chrome, VS Code and NetworkManager use underneath, talking over a
# real session bus.
#
#   docker build -f Dockerfile.ss -t binpass-ss .
#   docker run --rm binpass-ss
FROM golang:1.26-trixie

RUN apt-get update && apt-get install -y --no-install-recommends \
	dbus \
	dbus-x11 \
	libsecret-tools \
	age \
	&& rm -rf /var/lib/apt/lists/*

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ENV CGO_ENABLED=0
ENV BINPASS_CONFIG=/nonexistent.yaml

COPY scripts/ss-session.sh /usr/local/bin/ss-session.sh

CMD ["bash", "/usr/local/bin/ss-session.sh"]
