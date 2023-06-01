package middlewares

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	secret = "!_?z$Tf$o}iDcJQ4Yk|&H87dm5#ZO'hv"
)

// MockAuthGen is a mock implementation of the AuthGen interface
type MockAuthGen struct {
	fails bool
	Users map[string]UserData
}

func (m *MockAuthGen) SetNewCred(user string) error {
	return nil
}

func (m *MockAuthGen) GetUserData(user string) (*UserData, bool) {
	ud, ok := m.Users[user]
	return &ud, ok
}

func (m *MockAuthGen) Authenticate(user string, token string) error {

	return nil
}

func (m *MockAuthGen) GenerateToken(user string) (string, error) {
	if m.fails {
		return "", fmt.Errorf("Generate test error")
	}
	return "Generate-Token Success", nil
}

func TestLoginHandler(t *testing.T) {
	type testCases []struct {
		title    string
		user     string
		password string
		code     int
		expected string
		ma       AuthGen
	}

	cases := testCases{
		{
			title:    "Empty username password",
			user:     "",
			password: "",
			code:     http.StatusUnauthorized,
			ma: &MockAuthGen{
				Users: map[string]UserData{
					"user": {
						Password: "pass",
						Secret:   secret,
					},
				},
			},
		},
		{
			title:    "Empty username",
			user:     "",
			password: "pass",
			code:     http.StatusUnauthorized,
			ma: &MockAuthGen{
				Users: map[string]UserData{
					"user": {
						Password: "pass",
						Secret:   secret,
					},
				},
			},
		},
		{
			title:    "Empty password",
			user:     "user",
			password: "",
			code:     http.StatusUnauthorized,
			ma: &MockAuthGen{
				Users: map[string]UserData{
					"user": {
						Password: "pass",
						Secret:   secret,
					},
				},
			},
		},
		{
			title:    "Invalid user",
			user:     "user1",
			password: "pass",
			code:     http.StatusUnauthorized,
			expected: "Access denied",
			ma: &MockAuthGen{
				Users: map[string]UserData{
					"user": {
						Password: "pass",
						Secret:   secret,
					},
				},
			},
		},
		{
			title:    "Invalid password",
			user:     "user",
			password: "pass1",
			code:     http.StatusUnauthorized,
			expected: "Access denied",
			ma: &MockAuthGen{
				Users: map[string]UserData{
					"user": {
						Password: "pass",
						Secret:   secret,
					},
				},
			},
		},
		{
			title:    "Valid user and password but error generating token",
			user:     "user",
			password: "pass",
			code:     http.StatusInternalServerError,
			expected: "Generate test error",
			ma: &MockAuthGen{
				fails: true,
				Users: map[string]UserData{
					"user": {
						Password: "pass",
						Secret:   secret,
					},
				},
			},
		},
		{
			title:    "Valid user and password",
			user:     "user",
			password: "pass",
			code:     http.StatusCreated,
			expected: "Generate-Token Success",
			ma: &MockAuthGen{
				fails: false,
				Users: map[string]UserData{
					"user": {
						Password: "pass",
						Secret:   secret,
					},
				},
			},
		},
		{
			title:    "Generator coverage case",
			user:     "user",
			password: "pass",
			code:     http.StatusCreated,
			ma: &JWT{
				Users: map[string]UserData{
					"user": {
						Password: "pass",
						Secret:   "secret",
					},
				},
			},
		},
		{
			title:    "Generator coverage case",
			user:     "user",
			password: "pass",
			code:     http.StatusCreated,
			ma: &JWT{
				Users: map[string]UserData{
					"user": {
						Password: "pass",
						Secret:   secret,
						Exp:      23,
					},
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.title, func(t *testing.T) {
			jwtMiddleware := NewMiddleware(tc.ma)

			req, err := http.NewRequest("GET", "/login", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("username", tc.user)
			req.Header.Set("password", tc.password)
			recorder := httptest.NewRecorder()

			handler := http.HandlerFunc(jwtMiddleware.LoginHandler)
			handler.ServeHTTP(recorder, req)

			require.Equal(t, tc.code, recorder.Code)
			if tc.expected != "" {
				require.Equal(t, tc.expected, recorder.Body.String())
			}
		})
	}
}
func TestAuthHandlerValidToken(t *testing.T) {
	user := "user"
	authGen := &JWT{
		Users: map[string]UserData{
			user: {
				Password: "pass",
				Secret:   secret,
				Exp:      23,
			},
		},
	}
	jwtMiddleware := NewMiddleware(authGen)

	req, err := http.NewRequest("GET", "/protected", nil)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := getToken(user, jwtMiddleware)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("username", user)

	recorder := httptest.NewRecorder()

	handler := jwtMiddleware.AuthHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := r.Context().Value("user")
		require.Equal(t, user, u.(string))
	}))

	handler.ServeHTTP(recorder, req)
	require.Equal(t, http.StatusOK, recorder.Code)
}

func TestAuthHandlerInValidToken(t *testing.T) {
	user := "user"
	authGen := &JWT{
		Users: map[string]UserData{
			user: {
				Password: "pass",
				Secret:   secret,
				Exp:      23,
			},
		},
	}
	jwtMiddleware := NewMiddleware(authGen)

	req, err := http.NewRequest("GET", "/protected", nil)
	if err != nil {
		t.Fatal(err)
	}
	tok := "invalid-token"
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("username", user)

	recorder := httptest.NewRecorder()

	handler := jwtMiddleware.AuthHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Fail(t, "should not be called")
	}))

	handler.ServeHTTP(recorder, req)
	require.Equal(t, http.StatusUnauthorized, recorder.Code)
	require.Equal(t, "token contains an invalid number of segments", recorder.Body.String())
}

func TestAuthHandlerEmptyToken(t *testing.T) {
	user := "user"
	authGen := &JWT{
		Users: map[string]UserData{
			user: {
				Password: "pass",
				Secret:   secret,
				Exp:      23,
			},
		},
	}
	jwtMiddleware := NewMiddleware(authGen)

	req, err := http.NewRequest("GET", "/protected", nil)
	if err != nil {
		t.Fatal(err)
	}
	require.NoError(t, err)
	req.Header.Set("username", user)

	recorder := httptest.NewRecorder()

	handler := jwtMiddleware.AuthHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Fail(t, "should not be called")
	}))

	handler.ServeHTTP(recorder, req)
	require.Equal(t, http.StatusUnauthorized, recorder.Code)
	require.Equal(t, "token required", recorder.Body.String())
}

func getToken(user string, au *JWTMiddleware) (string, error) {

	req, err := http.NewRequest("GET", "/login", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("username", user)
	ud, b := au.AuthGen.GetUserData(user)
	if !b {
		return "", fmt.Errorf("error getting user data")
	}
	req.Header.Set("password", ud.Password)

	recorder := httptest.NewRecorder()

	handler := http.HandlerFunc(au.LoginHandler)
	handler.ServeHTTP(recorder, req)

	if http.StatusCreated != recorder.Code {
		return "", fmt.Errorf("error generating token")
	}
	return recorder.Body.String(), nil
}

func TestValidateSecret(t *testing.T) {
	type args struct {
		user   string
		secret string
	}
	tests := []struct {
		name   string
		args   args
		expect string
	}{
		// Invalid length
		{
			name: "Invalid length",
			args: args{
				user:   "user",
				secret: "Secret1!Secret1!Secret1!Secret1",
			},
			expect: "secret should be at least 32 characters",
		},
		// No uppercase
		{
			name: "No uppercase",
			args: args{
				user:   "user",
				secret: "secretsecretsecretsecretsecrets1",
			},
			expect: "secret should contain at least one uppercase character",
		},
		// No lowercase
		{
			name: "No lowercase",
			args: args{
				user:   "user",
				secret: "SECRETSECRETSECRETSECRETSECRETS1",
			},
			expect: "secret should contain at least one lowercase character",
		},
		// No number
		{
			name: "No number",
			args: args{
				user:   "user",
				secret: "SecretSecretSecretSecretSecretSe",
			},
			expect: "secret should contain at least one digit",
		},
		// No special character
		{
			name: "No special character",
			args: args{
				user:   "user",
				secret: "SecretSecretSecretSecretSecretS1",
			},
			expect: "secret should contain at least one special character",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := validateSecret(tt.args.user, tt.args.secret)
			require.Equal(t, tt.expect, actual.Error())
		})
	}
}

func TestJWT_CheckUpdatenewCred(t *testing.T) {
	var e uint64 = 1
	type fields struct {
		Users map[string]UserData
	}
	tests := []struct {
		name   string
		fields fields
	}{
		{
			name: "CheckUpdatenewCred",
			fields: fields{
				Users: map[string]UserData{
					"user": {
						Password:   "pass",
						Secret:     secret,
						Exp:        1,
						OldCredExp: &e,
						NewData: &UserData{
							Password: "pass1",
							Secret:   secret + "1",
							Exp:      33,
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &JWT{
				Users: tt.fields.Users,
			}
			a.CheckUpdateNewCred()
			d, ret := a.GetUserData("user")
			require.True(t, ret)
			require.Equal(t, "pass", d.Password)
			require.Equal(t, secret, d.Secret)

			time.Sleep(time.Minute + time.Second)

			d, ret = a.GetUserData("user")
			require.True(t, ret)
			require.Equal(t, "pass1", d.Password)
			require.Equal(t, secret+"1", d.Secret)
		})
	}
}
