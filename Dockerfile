FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /out/network-diagnose .

FROM gcr.io/distroless/static-debian12
COPY --from=build /out/network-diagnose /usr/local/bin/network-diagnose
ENTRYPOINT ["/usr/local/bin/network-diagnose"]
