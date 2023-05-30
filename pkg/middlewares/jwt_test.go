package middlewares

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
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
						Secret:   "secret",
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
						Secret:   "secret",
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
						Secret:   "secret",
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
						Secret:   "secret",
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
						Secret:   "secret",
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
						Secret:   "secret",
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
						Secret:   "secret",
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
				Secret:   "secret",
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
				Secret:   "secret",
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
				Secret:   "secret",
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
		name string
		args args
		want bool
	}{
		// Invalid length
		{
			name: "Invalid length",
			args: args{
				user:   "user",
				secret: "Sec1",
			},
			want: false,
		},
		// No uppercase
		{
			name: "No uppercase",
			args: args{
				user:   "user",
				secret: "secretsecretsecret1",
			},
			want: false,
		},
		// No lowercase
		{
			name: "No lowercase",
			args: args{
				user:   "user",
				secret: "SECRETSECRETSECRET1",
			},
			want: false,
		},
		// No number
		{
			name: "No number",
			args: args{
				user:   "user",
				secret: "SecretSecretSecret",
			},
			want: false,
		},
		// No special character
		{
			name: "No special character",
			args: args{
				user:   "user",
				secret: "SecretSecretSecret1",
			},
			want: false,
		},
		// Valid
		{
			name: "Valid",
			args: args{
				user:   "user",
				secret: "SecretSecretSecret1!",
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ValidateSecret(tt.args.user, tt.args.secret)
			require.Equal(t, got, tt.want)
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
						Secret:     "SecretSecretSecret1!",
						Exp:        23,
						OldCredExp: &e,
						NewData: &UserData{
							Password: "pass1",
							Secret:   "SecretSecretSecret12!",
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
			a.CheckUpdatenewCred()
			time.Sleep(1 * time.Minute)
			d, ret := a.GetUserData("user")
			require.True(t, ret)
			require.Equal(t, "pass1", d.Password)
			require.Equal(t, "SecretSecretSecret12!", d.Secret)
		})
	}
}
