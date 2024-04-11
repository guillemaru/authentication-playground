package main

import (
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

func main() {
	// Create a new router
	router := mux.NewRouter()

	// Attach CORS middleware
	router.Use(corsMiddleware)

	// Define routes
	router.HandleFunc("/login", handleRequest).Methods("POST", "OPTIONS")
	router.HandleFunc("/logout", handleRequest).Methods("POST", "OPTIONS")
	router.HandleFunc("/signup", handleRequest).Methods("POST", "OPTIONS")

	// Start the HTTP server and listen on port 8080
	log.Fatal(http.ListenAndServe(":8080", router))
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	// Set content type to JSON
	w.Header().Set("Content-Type", "application/json")

	// Handle POST request
	if r.Method == http.MethodPost {
		// Return status 200 for now
		w.WriteHeader(http.StatusOK)
		return
	}

	// Return method not allowed if request method is not POST
	w.WriteHeader(http.StatusMethodNotAllowed)
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set the expected origin
		expectedOrigin := "http://localhost:3000"

		// Get the actual origin from the request headers
		origin := r.Header.Get("Origin")

		// Compare the actual origin with the expected origin
		if origin != expectedOrigin {
			// If the origins don't match, return a CORS error
			http.Error(w, "CORS error: Unauthorized origin", http.StatusForbidden)
			return
		}

		// Set Access-Control-Allow-Origin header to allow requests only from the same origin
		w.Header().Set("Access-Control-Allow-Origin", expectedOrigin)

		// Set Access-Control-Allow-Methods header to allow only POST requests
		w.Header().Set("Access-Control-Allow-Methods", "POST")

		// Handle preflight requests
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Call the next handler in the chain
		next.ServeHTTP(w, r)
	})
}
