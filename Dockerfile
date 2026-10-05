# syntax=docker/dockerfile:1
ARG GO_VERSION=1.26.6
FROM golang:${GO_VERSION} AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# VERSION is the image tag and COMMIT the full source SHA, stamped into
# go-buildinfo and reported on the health check.
ARG VERSION=dev
ARG COMMIT=none
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X github.com/Bugs5382/go-buildinfo.Version=${VERSION} -X github.com/Bugs5382/go-buildinfo.Commit=${COMMIT}" \
    -o /out/ ./cmd/server ./cmd/identity-admin

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/server /server
COPY --from=build /out/identity-admin /identity-admin
COPY --from=build /src/migrations /migrations
ENV MIGRATIONS_DIR=/migrations
USER nonroot:nonroot
EXPOSE 9090 8080
ENTRYPOINT ["/server"]
