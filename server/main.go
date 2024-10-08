package main

import (
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/gofrs/uuid"
	"github.com/gorilla/mux"
	"go.etcd.io/bbolt"
)

// TODO: use a database for: keys, currentKid, tokensToBeRevoked

// Package-level variable to hold the database instance
var db *bbolt.DB

// keys for JWT signing
var keys = map[string]key{}
var currentKid = ""

var tokensToBeRevoked = []string{}

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
	// Open the database
	var err error
	db, err = openDatabase("credentialsdb.db")
	if err != nil {
		panic("could not initialise database")
	}
	defer db.Close()
	err = createBucket(db, "CredentialsBucket")
	if err != nil {
		panic("could not create credentials database bucket")
	}

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
