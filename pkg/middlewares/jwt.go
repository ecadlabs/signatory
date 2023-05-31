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
	GetUserData(user string) (*UserData, bool)
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

func ValidateSecret(user string, secret string) bool {
	// Check length
	if len(secret) < 16 {
		fmt.Println("JWT-Warning:Secret length is too short. It should be at least 16 characters.")
		return false
	}

	// Check if secret contains uppercase characters
	hasUppercase := false
	for _, c := range secret {
		if c >= 'A' && c <= 'Z' {
			hasUppercase = true
			break
		}
	}
	if !hasUppercase {
		fmt.Println("JWT-Warning:Secret should contain at least one uppercase character.")
		return false
	}

	// Check if secret contains lowercase characters
	hasLowercase := false
	for _, c := range secret {
		if c >= 'a' && c <= 'z' {
			hasLowercase = true
			break
		}
	}
	if !hasLowercase {
		fmt.Println("JWT-Warning:Secret should contain at least one lowercase character.")
		return false
	}

	// Check if secret contains digits
	hasDigit := false
	for _, c := range secret {
		if c >= '0' && c <= '9' {
			hasDigit = true
			break
		}
	}
	if !hasDigit {
		fmt.Println("JWT-Warning:Secret should contain at least one digit.")
		return false
	}

	// Check if secret contains special characters
	hasSpecialChar := false
	// specialChars := "!@#$%^&*()-=_+[]{}|;:,.<>/?"
	for _, c := range secret {
		if c >= 32 && c <= 126 && !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
			hasSpecialChar = true
			break
		}
	}
	if !hasSpecialChar {
		fmt.Println("JWT-Warning:Secret should contain at least one special character.")
		return false
	}

	return true
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

	ud, ok := m.AuthGen.GetUserData(user)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Access denied"))
		return
	}
	if ud.Password != pass {
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
		ctx := context.WithValue(r.Context(), "user", user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// JWT contains the configuration for JWT tokens
type JWT struct {
	Users map[string]UserData `yaml:"users"`
}

type UserData struct {
	Password   string  `yaml:"password"`
	Exp        uint64  `yaml:"jwt_exp"`
	Secret     string  `yaml:"secret"`
	OldCredExp *uint64 `yaml:"old_cred_exp,omitempty"`
	useNewCred bool
	NewData    *UserData `yaml:"new_data"`
}

func (j *JWT) SetNewCred(user string) error {
	if u, ok := j.Users[user]; ok {
		u.useNewCred = true
		j.Users[user] = u
		return nil
	}
	return fmt.Errorf("JWT: user not found")
}

func (j *JWT) GetUserData(user string) (*UserData, bool) {
	if u, ok := j.Users[user]; ok {
		if u.useNewCred {
			return u.NewData, true
		}
		return &u, true
	}
	return nil, false
}

// GenerateToken generates a new token for the given user
func (j *JWT) GenerateToken(user string) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["user"] = user
	ud, ok := j.GetUserData(user)
	if ok {
		if ud.Exp == 0 {
			var mt = uint64(math.MaxUint64)
			claims["exp"] = time.Now().Add(time.Hour * time.Duration(mt)).Unix()
		} else {
			claims["exp"] = time.Now().Add(time.Minute * time.Duration(ud.Exp)).Unix()
		}
	} else {
		return "", fmt.Errorf("JWT: user not found")
	}
	token.Claims = claims
	return token.SignedString([]byte(ud.Secret))
}

// Authenticate authenticates the given token
func (j *JWT) Authenticate(user string, token string) error {
	ud, ok := j.GetUserData(user)
	if ok {
		t, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
			return []byte(ud.Secret), nil
		})
		if err != nil {
			return err
		}
		if _, ok := t.Claims.(jwt.MapClaims); ok && t.Valid {
			return nil
		}
	} else {
		return fmt.Errorf("JWT: user not found")
	}
	return fmt.Errorf("JWT: invalid token")
}

func (j *JWT) CheckUpdatenewCred() {
	for user, data := range j.Users {
		if data.NewData != nil {
			go func(u string, exp *uint64) {
				if exp == nil {
					*exp = 30
				}
				timer := time.NewTimer(time.Minute * time.Duration(*exp))
				<-timer.C
				err := j.SetNewCred(u)
				if err != nil {
					fmt.Println("JWT: Failed to set new user config for ", u, ":", err)
					return
				}
			}(user, data.OldCredExp)
			ValidateSecret(user, data.NewData.Secret)
		}
		ValidateSecret(user, data.Secret)
	}
}
