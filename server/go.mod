module loginserver

go 1.22

toolchain go1.22.5

require (
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/gofrs/uuid v4.4.0+incompatible
	github.com/gorilla/mux v1.8.1
	go.etcd.io/bbolt v1.3.10
	golang.org/x/crypto v0.22.0
)

require golang.org/x/sys v0.19.0 // indirect
