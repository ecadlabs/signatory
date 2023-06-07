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
	GetUserData(user string) (*UserData, bool)
	Authenticate(user string, token string) (string, error)
	GenerateToken(user string, pass string) (string, error)
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

	ud, ok := m.AuthGen.GetUserData(user)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Access denied"))
		return
	}
	if ud.Password != pass {
		if ud.NewData != nil {
			if ud.NewData.Password != pass {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("Access denied"))
				return
			}
		} else {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Access denied"))
			return
		}
	}

	token, err := m.AuthGen.GenerateToken(user, pass)
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
		var u string
		var err error
		if r.URL.Path == "/login" {
			next.ServeHTTP(w, r)
			return
		}
		token := r.Header.Get("Authorization")
		user := r.Header.Get("username")

		if token != "" {
			token = strings.TrimPrefix(token, "Bearer ")
			u, err = m.AuthGen.Authenticate(user, token)
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
		ctx := context.WithValue(r.Context(), "user", u)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// JWT contains the configuration for JWT tokens
type JWT struct {
	Users map[string]UserData `yaml:"users"`
}

type UserData struct {
	Password   string    `yaml:"password"`
	Exp        uint64    `yaml:"jwt_exp"`
	Secret     string    `yaml:"secret"`
	OldCredExp *uint64   `yaml:"old_cred_exp,omitempty"`
	NewData    *UserData `yaml:"new_data"`
}

func (j *JWT) SetNewCred(user string) error {
	if u, ok := j.Users[user]; ok {
		u.Password = u.NewData.Password
		u.Secret = u.NewData.Secret
		u.Exp = u.NewData.Exp
		u.NewData = nil
		j.Users[user] = u
		return nil
	}
	return fmt.Errorf("JWT: user not found")
}

func (j *JWT) GetUserData(user string) (*UserData, bool) {
	if u, ok := j.Users[user]; ok {
		return &u, true
	}
	return nil, false
}

// GenerateToken generates a new token for the given user
func (j *JWT) GenerateToken(user string, pass string) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["user"] = user
	ud, ok := j.GetUserData(user)
	if pass != ud.Password {
		ud = ud.NewData
	}
	if ok {
		if ud.Exp == 0 {
			ud.Exp = 60
		}
		claims["exp"] = time.Now().Add(time.Minute * time.Duration(ud.Exp)).Unix()
	} else {
		return "", fmt.Errorf("JWT: user not found")
	}
	token.Claims = claims
	return token.SignedString([]byte(ud.Secret))
}

// Authenticate authenticates the given token
func (j *JWT) Authenticate(user string, token string) (string, error) {
	var tok *jwt.Token
	var err error
	ud, ok := j.GetUserData(user)
	if ok {
		tok, err = jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
			return []byte(ud.Secret), nil
		})
		if err != nil {
			if ud.NewData != nil {
				tok, err = jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
					return []byte(ud.NewData.Secret), nil
				})
			}
			return "", err
		}
		if tu := tok.Claims.(jwt.MapClaims)["user"]; tu != nil {
			if tu.(string) != user {
				fmt.Println("JWT_Warning: Suspicious activity detected, token user is not the same as the user in the request")
				return "", fmt.Errorf("JWT: invalid token")
			}
		} else {
			return "", fmt.Errorf("JWT: invalid token")
		}
		if _, ok := tok.Claims.(jwt.MapClaims); ok && tok.Valid {
			return tok.Claims.(jwt.MapClaims)["user"].(string), nil
		}
	} else {
		return "", fmt.Errorf("JWT: user not found")
	}
	return "", fmt.Errorf("JWT: invalid token")
}

func (j *JWT) CheckUpdateNewCred() error {
	for user, data := range j.Users {
		if data.NewData != nil {
			if data.NewData.Password == data.Password || data.NewData.Secret == data.Secret {
				return fmt.Errorf("JWT: new credentials are same as old for user %s", user)
			}
			if e := validateSecretAndPass([]string{data.NewData.Password, data.NewData.Secret}); e != nil {
				return fmt.Errorf("JWT:config validation failed for user %s: %e", user, e)
			}
			go func(u string, exp *uint64) error {
				if exp == nil {
					*exp = 30
				}
				timer := time.NewTimer(time.Minute * time.Duration(*exp))
				<-timer.C
				err := j.SetNewCred(u)
				if err != nil {
					return fmt.Errorf("JWT: Failed to set new user config for %s: %e", u, err)
				}
				return nil
			}(user, data.OldCredExp)
		}
		if e := validateSecretAndPass([]string{data.Password, data.Secret}); e != nil {
			return fmt.Errorf("JWT:config validation failed for user %s: %e", user, e)
		}
	}
	return nil
}

func validateSecretAndPass(secret []string) error {
	var length int = 16
	var stype string = "password"
	for _, s := range secret {
		// Check length
		if len(s) < length {
			return fmt.Errorf("%s should be at least %d characters", stype, length)
		}
		// Check if secret contains uppercase characters
		hasUppercase := false
		for _, c := range s {
			if c >= 'A' && c <= 'Z' {
				hasUppercase = true
				break
			}
		}
		if !hasUppercase {
			return fmt.Errorf("%s should contain at least one uppercase character", stype)
		}

		// Check if secret contains lowercase characters
		hasLowercase := false
		for _, c := range s {
			if c >= 'a' && c <= 'z' {
				hasLowercase = true
				break
			}
		}
		if !hasLowercase {
			return fmt.Errorf("%s should contain at least one lowercase character", stype)
		}

		// Check if secret contains digits
		hasDigit := false
		for _, c := range s {
			if c >= '0' && c <= '9' {
				hasDigit = true
				break
			}
		}
		if !hasDigit {
			return fmt.Errorf("%s should contain at least one digit", stype)
		}

		// Check if secret contains special characters
		hasSpecialChar := false
		for _, c := range s {
			if c >= 32 && c <= 126 && !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
				hasSpecialChar = true
				break
			}
		}
		if !hasSpecialChar {
			return fmt.Errorf("%s should contain at least one special character", stype)
		}
		length = 32
		stype = "secret"
	}
	return nil
}
