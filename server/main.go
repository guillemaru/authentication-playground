package main

import (
	"crypto/rand"	
	"io"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gofrs/uuid"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
	"html/template"
	"log"
	mrand "math/rand"
	"net/http"
	"time"
)

const loggedInTemplate = `
	<div id="loggedindiv">
		<h1>Logged in as {{.Username}}</h1>
		<button hx-post="/logout" hx-target="#loggedindiv" hx-swap="outerHTML">Logout</button>
	</div>`

type Credentials struct {
    Username string
    Password string
}
type UserClaims struct {
	jwt.StandardClaims
	SessionID int64
	Username string
}

type key struct {
	key []byte
	created time.Time
}

// TODO: use a database for: keys, currentKid, credentials, tokensToBeRevoked

// keys for JWT signing
var keys = map[string]key{}
var currentKid = ""
// Local map to store user/hashed password pairs
var credentials = map[string][]byte{}
var tokensToBeRevoked = []string{}


func (u *UserClaims) Valid() error {
	if !u.VerifyExpiresAt(time.Now().Unix(), true) {
		return fmt.Errorf("Token has expired")
	}

	if u.SessionID == 0 {
		return fmt.Errorf("Invalid session ID")
	}

	_, exists := credentials[u.Username]
	if !exists {
		return fmt.Errorf("Invalid username")
	}

	return nil
}


func generateSessionID() int64 {
    timestamp := time.Now().Unix()
    mrand.Seed(time.Now().UnixNano())
    randomNum := mrand.Int63n(1000000)
    sessionID := timestamp*1000000 + randomNum
    return sessionID
}


func generateNewKey() error {
	newKey := make([]byte, 64)
	_, err := io.ReadFull(rand.Reader, newKey)
	if err != nil {
		return fmt.Errorf("Error in generateNewKey while generating key: %w", err)
	}

	uid, err := uuid.NewV4()
	if err != nil {
		return fmt.Errorf("Error in generateNewKey while generating kid: %w", err)
	}
	//TODO: keys should be a database so here we should be creating a new entry on it
	keys[uid.String()] = key{
		key: newKey,
		created: time.Now(),
	}
	currentKid = uid.String()

	return nil
}

func main() {
	credentials = make(map[string][]byte)
	generateNewKey() // for the JWT signing
	//TODO: when "keys" will be a database, here we should delete all the entries that have a "created" older than some time (e.g. one week)
	// Create a new router
	router := mux.NewRouter()

	// Attach CO::::RS middleware
	router.Use(corsMiddleware)

	// Define routes
	router.HandleFunc("/", handleIndexRequest).Methods("GET", "OPTIONS")
	router.HandleFunc("/login", handleLoginRequest).Methods("POST", "OPTIONS")
	router.HandleFunc("/logout", handleLogoutRequest).Methods("POST", "OPTIONS")
	router.HandleFunc("/signup", handleSignupRequest).Methods("POST", "OPTIONS")

	// Start the HTTP server and listen on port 8080
	log.Fatal(http.ListenAndServe(":8080", router))
}

func handleIndexRequest(w http.ResponseWriter, r *http.Request) {
	html := `
	<!DOCTYPE html>
	<html lang="en">
	<head>
	    <meta charset="UTF-8">
	    <meta name="viewport" content="width=device-width, initial-scale=1.0">
	    <title>Authentication playground</title>
	    <script src="https://unpkg.com/htmx.org/dist/htmx.js"></script>
	</head>
	<body>
	    <div id="signupform">
		<h1>Sign up</h1>
		<form hx-post="/signup" hx-target="#signupform" hx-swap="outerHTML">
		    <input type="text" id="username" name="username" placeholder="Username" required><br>
		    <input type="password" id="password" name="password" placeholder="Password" required><br>
		    <input type="submit" value="Submit">
		</form>
	    </div>
	</body>
	</html>
	`
	io.WriteString(w, html)
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
	htmlContent := `
	<div id="loginform">
		<h1>Login</h1>
		<form hx-post="/login" hx-target="#loginform" hx-swap="outerHTML">
		    <input type="text" id="username" name="username" placeholder="Username" required><br>
		    <input type="password" id="password" name="password" placeholder="Password" required><br>
		    <input type="submit" value="Submit">
		</form>
	</div>
	`
	fmt.Fprint(w, htmlContent)
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
		http.Error(w, "Username does not exist.", http.StatusForbidden)
		return
	}
	if err := bcrypt.CompareHashAndPassword(storedHashedPassword, []byte(creds.Password)); err != nil {
		http.Error(w, "Invalid password", http.StatusForbidden)
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
		Path:    "/", // Cookie is accessible from all paths
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

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Hx-Current-Url, Hx-Request, Hx-Target, Hx-Trigger")

		// Handle preflight requests
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Call the next handler in the chain
		next.ServeHTTP(w, r)
	})
}

func createToken(c *UserClaims) (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodHS512, c)
	t.Header["kid"] = currentKid
	signedToken, err := t.SignedString(keys[currentKid].key)
	if err != nil {
		return "", fmt.Errorf("Error in createToken when signing token: %w", err)
	}
	return signedToken, nil
}

func parseToken(signedToken string) (*UserClaims, error) {
	t, err := jwt.ParseWithClaims(signedToken, &UserClaims{}, func (t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != jwt.SigningMethodHS512.Alg() {
			return nil, fmt.Errorf("Invalid signing algorithm")
		}

		kid, ok := t.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("Invalid key ID")
		}

		k, ok := keys[kid]
		if !ok {
			return nil, fmt.Errorf("Invalid key ID")
		}

		return k.key, nil
	})
	if err != nil {
		return nil, fmt.Errorf("Error in parseToken while parsing token: %w", err)
	}

	if !t.Valid {
		return nil, fmt.Errorf("Error in parseToken, token is not valid")
	}

	return t.Claims.(*UserClaims), nil
}

func addTokenToBeRevoked(newToken string) {
	tokensToBeRevoked = append(tokensToBeRevoked, newToken)
}

func revokeToken(toRemove string) error {
	for i, k := range tokensToBeRevoked {
		if k == toRemove {
			// Remove the key from the slice by slicing it
			tokensToBeRevoked = append(tokensToBeRevoked[:i], tokensToBeRevoked[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("Key not found")
}
