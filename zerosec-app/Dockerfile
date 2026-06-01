# Build stage
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/zerosec-app .

# Run stage
FROM alpine:3.20
WORKDIR /app
COPY --from=build /out/zerosec-app .
# The server resolves these paths relative to its working directory.
COPY home.html register.html ./
COPY static ./static
EXPOSE 8081
CMD ["./zerosec-app"]
