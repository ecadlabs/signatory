package middlewares

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
)

// AuthGen is an interface for authenticating users
type AuthGen interface {
	Authenticate(user string, token string) error
	GenerateToken(user string) (string, error)
}

// Middleware is a middleware that authenticates users
type JWTMiddleware struct {
	AuthGen AuthGen
}

// NewMiddleware creates a new Middleware
func NewMiddleware(a AuthGen) *JWTMiddleware {
	return &JWTMiddleware{a}
}

// Handler is a middleware handler
func (m *JWTMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		user := r.Header.Get("user")
		if token != "" {
			token = strings.TrimPrefix(token, "Bearer ")
			err := m.AuthGen.Authenticate(user, token)
			if err == nil {
				ctx := context.WithValue(r.Context(), "user", &user)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
		} else {
			//TBD: Verify the user and password
			token, err := m.AuthGen.GenerateToken(user)
			if err == nil {
				w.Write([]byte(err.Error()))
				return
			}
			w.Write([]byte(token))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// JWT contains the configuration for JWT tokens
type JWT struct {
	Users map[string]UserData `yaml:"users"`
}

type UserData struct {
	Expires time.Duration `yaml:"expires"`
	secret  string        `yaml:"secret"`
}

// GenerateToken generates a new token for the given user
func (j *JWT) GenerateToken(user string) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["user"] = user
	claims["exp"] = time.Now().Add(time.Second * j.Users[user].Expires).Unix()
	token.Claims = claims
	return token.SignedString([]byte(j.Users[user].secret))
}

// Authenticate authenticates the given token
func (j *JWT) Authenticate(user string, token string) error {
	t, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return []byte(j.Users[user].secret), nil
	})
	if err != nil {
		return err
	}
	if !t.Valid {
		// return t.Claims.(jwt.MapClaims)["user"].(string), nil
		return fmt.Errorf("invalid token")
	}
	return nil
}
