package middlewares

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
)

// AuthGen is an interface that generates token authenticates the same
type AuthGen interface {
	Authenticate(user string, token string) error
	GenerateToken(user string) (string, error)
}

// JWTMiddleware is an AuthGen implementation that uses JWT tokens
type JWTMiddleware struct {
	AuthGen AuthGen
}

// NewMiddleware creates a new JWTMiddleware
func NewMiddleware(a AuthGen) *JWTMiddleware {
	return &JWTMiddleware{a}
}

// Handler is a middleware handler
func (m *JWTMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		user := r.Header.Get("username")
		pass := r.Header.Get("password")

		if token != "" {
			token = strings.TrimPrefix(token, "Bearer ")
			err := m.AuthGen.Authenticate(user, token)
			if err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
		} else {
			if user == "" || pass == "" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if m.AuthGen.(*JWT).Users[user].Password != pass {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			token, err := m.AuthGen.GenerateToken(user)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(err.Error()))
				return
			}
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(token))
			return
		}
		ctx := context.WithValue(r.Context(), "user", &user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// JWT contains the configuration for JWT tokens
type JWT struct {
	Users map[string]UserData `yaml:"users"`
}

type UserData struct {
	Password string        `yaml:"password"`
	Expires  time.Duration `yaml:"expires"`
	Secret   string        `yaml:"secret"`
}

// GenerateToken generates a new token for the given user
func (j *JWT) GenerateToken(user string) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["user"] = user
	claims["exp"] = time.Now().Add(time.Minute * j.Users[user].Expires).Unix()
	token.Claims = claims
	return token.SignedString([]byte(j.Users[user].Secret))
}

// Authenticate authenticates the given token
func (j *JWT) Authenticate(user string, token string) error {
	t, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return []byte(j.Users[user].Secret), nil
	})
	if err != nil {
		return err
	}
	if _, ok := t.Claims.(jwt.MapClaims); ok && t.Valid {
		return nil
	}
	return fmt.Errorf("invalid token")
}