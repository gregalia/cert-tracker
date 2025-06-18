# syntax=docker/dockerfile:1
FROM alpine:3.22.0 AS go-build

SHELL ["/bin/ash", "-eo", "pipefail", "-c"]

ARG CI
ARG PATH="/usr/local/go/bin:${PATH}"
ARG CGO_ENABLED=0

WORKDIR /build
COPY go.* ./

# hadolint ignore=SC2086,DL3018
RUN <<HEREDOC
  GO_VERSION=$(
    awk '$1 == "go" {print $2}' go.mod
  )
  ARCH=$(
    uname --machine |
    awk '{sub("aarch","arm"); sub("x86_","amd"); print}'
  )

  apk upgrade
  apk add --no-cache \
    ca-certificates \
    curl~8.14

  curl --fail --location --show-error https://golang.org/dl/go${GO_VERSION}.linux-${ARCH}.tar.gz |
    tar x -zf - -C /usr/local

  go mod download
HEREDOC

COPY ./ ./
RUN <<HEREDOC
  if [ "${CI}" = true ]; then
    echo "BUILD: CI"
    GOOS=linux GOARCH=arm64 go build
  else
    echo "BUILD: DEV"
    go build
  fi
HEREDOC

FROM alpine:3.22.0

WORKDIR /app
COPY --from=go-build /build/cert-tracker ./
COPY config.json ./

ENTRYPOINT ["./cert-tracker"]
