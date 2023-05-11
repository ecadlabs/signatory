package middlewares

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// MockAuthGen is a mock implementation of the AuthGen interface
type MockAuthGen struct {
	fails bool
	Users map[string]UserData
}

func (m *MockAuthGen) GetUserData(user string) (UserData, bool) {
	ud, ok := m.Users[user]
	return ud, ok
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
		ma       *MockAuthGen
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
