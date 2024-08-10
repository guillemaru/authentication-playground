package main

import (
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type Credentials struct {
	Username string
	Password string
}
type UserClaims struct {
	jwt.StandardClaims
	SessionID uint64
	Username  string
}

func (u *UserClaims) Valid() error {
	if !u.VerifyExpiresAt(time.Now().Unix(), true) {
		return fmt.Errorf("token has expired")
	}

	if u.SessionID == 0 {
		return fmt.Errorf("invalid session ID")
	}

	_, err := getCredential(db, "CredentialsBucket", u.Username)

	if err != nil {
		return fmt.Errorf("invalid username")
	}

	return nil
}

// Secret key used for JWT signing
// Timestamp used for rotating keys
type key struct {
	key     []byte
	created time.Time
}
