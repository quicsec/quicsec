# Quicsec
Security wrapper for QUIC protocol.

This project uses [quic-go](https://github.com/lucas-clemente/quic-go) as QUIC implementation.

# QUICk start

Export environment variables:

```
export CERT_FILE=/foo/bar/certs/server.pem
export KEY_FILE=/foo/bar/certs/server.key
```

Run the server app:

```
cd quicsec/examples
go run main.go -www ./www -bind localhost:4433 -v
```
