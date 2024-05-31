FROM golang:latest AS go-builder

WORKDIR /app/src

COPY . .
RUN go mod download
RUN go build  -o main .
RUN chmod +x main

ENTRYPOINT [ "./main" ]