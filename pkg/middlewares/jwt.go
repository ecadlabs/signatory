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
	fmt.Println("Abi-->JWT Middleware Handler")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		user := r.Header.Get("username")
		pass := r.Header.Get("password")
		fmt.Println("Abi-->Token", token)
		if token != "" {
			token = strings.TrimPrefix(token, "Bearer ")
			err := m.AuthGen.Authenticate(user, token)
			if err != nil {
				fmt.Println("Abi-->Token-Error", err)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
		} else {
			if user == "" || pass == "" {
				w.WriteHeader(http.StatusUnauthorized)
			}
			if m.AuthGen.(*JWT).Users[user].Password != pass {
				w.WriteHeader(http.StatusUnauthorized)
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
	claims["exp"] = time.Now().Add(time.Second * j.Users[user].Expires).Unix()
	token.Claims = claims
	return token.SignedString([]byte(j.Users[user].Secret))
}

// Authenticate authenticates the given token
func (j *JWT) Authenticate(user string, token string) error {
	t, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return []byte(j.Users[user].Secret), nil
	})
	if err != nil {
		fmt.Println("Abi-->Authenticate-Error", err)
		return err
	}
	if claims, ok := t.Claims.(jwt.MapClaims); ok && t.Valid {
		if claims.VerifyExpiresAt(int64(j.Users[user].Expires.Seconds()), true) {
			return fmt.Errorf("token expired")
		}
		return nil
	}

	return fmt.Errorf("invalid token")

}
