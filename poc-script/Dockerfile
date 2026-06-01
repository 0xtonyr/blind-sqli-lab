# Build stage
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY poc-bsqli.go .
RUN CGO_ENABLED=0 go build -o /out/poc poc-bsqli.go

# Run stage
FROM alpine:3.20
COPY --from=build /out/poc /usr/local/bin/poc
ENTRYPOINT ["poc"]
