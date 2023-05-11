package middlewares

import (
	"context"
	"fmt"
	"math"
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
func (m *JWTMiddleware) LoginHandler(w http.ResponseWriter, r *http.Request) {
	user := r.Header.Get("username")
	pass := r.Header.Get("password")
	if user == "" || pass == "" {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("username and password required"))
		return
	}

	cpass, ok := m.AuthGen.(*JWT).Users[user]
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Access denied"))
		return
	}
	if cpass.Password != pass {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Access denied"))
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
}

// Handler is a middleware handler
func (m *JWTMiddleware) AuthHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			next.ServeHTTP(w, r)
			return
		}
		token := r.Header.Get("Authorization")
		user := r.Header.Get("username")

		if token != "" {
			token = strings.TrimPrefix(token, "Bearer ")
			err := m.AuthGen.Authenticate(user, token)
			if err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(err.Error()))
				return
			}
		} else {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("token required"))
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
	Password string `yaml:"password"`
	Exp      uint64 `yaml:"jwt_exp"`
	Secret   string `yaml:"secret"`
}

// GenerateToken generates a new token for the given user
func (j *JWT) GenerateToken(user string) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["user"] = user
	if j.Users[user].Exp == 0 {
		var mt = uint64(math.MaxUint64)
		claims["exp"] = time.Now().Add(time.Hour * time.Duration(mt)).Unix()
	} else {
		claims["exp"] = time.Now().Add(time.Minute * time.Duration(j.Users[user].Exp)).Unix()
	}
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
