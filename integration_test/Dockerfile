FROM golang:1.19-alpine

RUN apkArch="$(apk --print-arch)" && \
	case "$apkArch" in \
	"x86_64") \
	;; \
	'aarch64') \
	TEZOS_CLIENT_ARCH="-arm64" \
	;; \
	*) echo >&2 "error: unsupported architecture '$apkArch'"; exit 1 \
	;; \
	esac && \
	wget -O /usr/local/bin/octez-client https://github.com/serokell/tezos-packaging/releases/latest/download/octez-client${TEZOS_CLIENT_ARCH} && chmod a+x /usr/local/bin/octez-client
RUN apk add --no-cache linux-headers gcc musl-dev

WORKDIR /app
COPY . .
RUN go mod download all
ENV ENV_NODE_ADDR=https://ghostnet.ecadinfra.com
ENV TEZOS_CLIENT_UNSAFE_DISABLE_DISCLAIMER=Y

ENTRYPOINT [ "/bin/sh", "-c" ]
CMD [ "/usr/local/go/bin/go test -v -tags integration ./..." ]
