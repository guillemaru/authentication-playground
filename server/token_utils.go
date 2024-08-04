package main

import (
	"fmt"

	"github.com/dgrijalva/jwt-go"
)

func createToken(c *UserClaims) (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodHS512, c)
	t.Header["kid"] = currentKid
	signedToken, err := t.SignedString(keys[currentKid].key)
	if err != nil {
		return "", fmt.Errorf("error in createToken when signing token: %w", err)
	}
	return signedToken, nil
}

func parseToken(signedToken string) (*UserClaims, error) {
	t, err := jwt.ParseWithClaims(signedToken, &UserClaims{}, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != jwt.SigningMethodHS512.Alg() {
			return nil, fmt.Errorf("invalid signing algorithm")
		}

		kid, ok := t.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("invalid key ID")
		}

		k, ok := keys[kid]
		if !ok {
			return nil, fmt.Errorf("invalid key ID")
		}

		return k.key, nil
	})
	if err != nil {
		return nil, fmt.Errorf("error in parseToken while parsing token: %w", err)
	}

	if !t.Valid {
		return nil, fmt.Errorf("error in parseToken, token is not valid")
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
	return fmt.Errorf("key not found")
}

func tokenIsRevoked(token string) bool {
	for _, k := range tokensToBeRevoked {
		if k == token {
			return false
		}
	}
	return true
}
