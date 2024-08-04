package main

import (
	"fmt"
	"html/template"
	"io"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

func handleIndexRequest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	io.WriteString(w, indexBegin)
	defer io.WriteString(w, indexEnd)
	sessionToken, err := r.Cookie("session_token")
	if err != nil {
		io.WriteString(w, signupTemplate)
		return
	}

	// Access the value of the cookie
	tokenString := sessionToken.Value
	userClaims, err := parseToken(tokenString)
	if err != nil || tokenIsRevoked(tokenString) {
		io.WriteString(w, signupTemplate)
		return
	}
	// Return the logged in template
	tmpl, err := template.New("loggedin").Parse(loggedInTemplate)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	data := struct{ Username string }{
		Username: userClaims.Username,
	}
	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

}

func handleSignupRequest(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	// Get username and password from request body
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Failed to parse form data", http.StatusBadRequest)
		return
	}
	username := r.Form.Get("username")
	password := r.Form.Get("password")
	if username == "" || password == "" {
		http.Error(w, "Missing username or password", http.StatusBadRequest)
		return
	}
	creds := Credentials{
		Username: username,
		Password: password,
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(creds.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Unknown error", http.StatusInternalServerError)
		return
	}
	credentials[creds.Username] = hashedPassword
	w.Header().Set("Content-Type", "text/html")

	fmt.Fprint(w, loginTemplate)
}

func handleLoginRequest(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	// Get username and password from request body
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Failed to parse form data", http.StatusBadRequest)
		return
	}
	username := r.Form.Get("username")
	password := r.Form.Get("password")
	if username == "" || password == "" {
		http.Error(w, "Missing username or password", http.StatusBadRequest)
		return
	}
	creds := Credentials{
		Username: username,
		Password: password,
	}

	// Check if the password matches the stored password
	storedHashedPassword, exists := credentials[creds.Username]
	if !exists {
		fmt.Fprint(w, invalidCredentialsTemplate)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if err := bcrypt.CompareHashAndPassword(storedHashedPassword, []byte(creds.Password)); err != nil {
		fmt.Fprint(w, invalidCredentialsTemplate)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	// Create a session token (JWT) and send it back as a cookie
	userclaims := &UserClaims{
		StandardClaims: jwt.StandardClaims{
			// Set the expiration time to one hour from now
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
		},
		SessionID: generateSessionID(),
		Username:  creds.Username,
	}
	tokenString, err := createToken(userclaims)
	if err != nil {
		http.Error(w, "Unknown error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:    "session_token",
		Value:   tokenString,
		Expires: time.Now().UTC().Add(24 * time.Hour), // this expiration is an additional layer of control on the client side
		Path:    "/",                                  // Cookie is accessible from all paths
	})
	addTokenToBeRevoked(tokenString)
	w.Header().Set("Content-Type", "text/html")
	tmpl, err := template.New("loggedin").Parse(loggedInTemplate)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	data := struct{ Username string }{
		Username: creds.Username,
	}
	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

func handleServeLoginRequest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	io.WriteString(w, loginTemplate)
}

func handleLogoutRequest(w http.ResponseWriter, r *http.Request) {
	// Read the value of the "session_token" cookie from the request
	w.Header().Set("Content-Type", "text/html")
	sessionToken, err := r.Cookie("session_token")
	if err != nil {
		http.Error(w, "Failed to read cookie", http.StatusBadRequest)
		return
	}

	// Access the value of the cookie
	tokenString := sessionToken.Value
	_, err = parseToken(tokenString)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	err = revokeToken(tokenString)
	if err != nil {
		htmlContent := `
		<h1>You are not logged in</h1>
		`
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, htmlContent)
		return
	}
	htmlContent := `
	<h1>Logout successful</h1>
	`
	fmt.Fprint(w, htmlContent)
}
