# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM golang:1.23.2-alpine AS build
ARG TARGETOS=linux
ARG TARGETARCH
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal

RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -buildvcs=false -ldflags="-s -w" -o /out/wv-9p ./cmd/wv-9p

FROM scratch
COPY --from=build /out/wv-9p /wv-9p
USER 65532:65532
EXPOSE 5640/tcp
ENTRYPOINT ["/wv-9p"]
CMD ["-root", "/srv/weaverssh-9p-root", "-listen", "0.0.0.0:5640", "-json"]
