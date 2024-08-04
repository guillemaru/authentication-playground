package main

import (
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	mrand "math/rand"
	"net/http"
	"time"

	"github.com/gofrs/uuid"
	"github.com/gorilla/mux"
)

// TODO: use a database for: keys, currentKid, credentials, tokensToBeRevoked

// keys for JWT signing
var keys = map[string]key{}
var currentKid = ""

// Local map to store user/hashed password pairs
var credentials = map[string][]byte{}
var tokensToBeRevoked = []string{}

// For JWT UserClaims
func generateSessionID() uint64 {
	return mrand.Uint64()
}

// Secret key for the JWT signing
func generateNewKey() error {
	newKey := make([]byte, 64)
	_, err := io.ReadFull(rand.Reader, newKey)
	if err != nil {
		return fmt.Errorf("error in generateNewKey while generating key: %w", err)
	}

	keyId, err := uuid.NewV4()
	keyIdString := keyId.String()
	if err != nil {
		return fmt.Errorf("error in generateNewKey while generating kid: %w", err)
	}
	//TODO: keys should be a database so here we should be creating a new entry on it
	keys[keyIdString] = key{
		key:     newKey,
		created: time.Now(),
	}
	currentKid = keyIdString

	return nil
}

func main() {
	credentials = make(map[string][]byte)
	generateNewKey()
	//TODO: when "keys" will be a database, here we should delete all the entries that have a "created" older than some time (e.g. one week)
	// Create a new router
	router := mux.NewRouter()

	// Define routes
	router.HandleFunc("/", handleIndexRequest).Methods("GET", "OPTIONS")
	router.HandleFunc("/login", handleLoginRequest).Methods("POST", "OPTIONS")
	router.HandleFunc("/servelogin", handleServeLoginRequest).Methods("GET")
	router.HandleFunc("/logout", handleLogoutRequest).Methods("POST", "OPTIONS")
	router.HandleFunc("/signup", handleSignupRequest).Methods("POST", "OPTIONS")

	// Uncomment this line to serve http instead of https if you do not want to bother with browser security restrictions
	//log.Fatal(http.ListenAndServe(":8080", router))

	// Start the HTTPS server
	cert, err := generateTLSCertificate()
	if err != nil {
		log.Fatalf("failed to generate TLS certificate: %v", err)
	}
	server := &http.Server{
		Addr:    ":8443",
		Handler: router,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
	}
	err = server.ListenAndServeTLS("", "")
	if err != nil {
		log.Fatalf("failed to start https server: %v", err)
	}
}
