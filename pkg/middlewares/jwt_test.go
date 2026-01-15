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

func (m *MockAuthGen) Authenticate(user string, token string) (string, error) {

	return "", nil
}

func (m *MockAuthGen) GenerateToken(user string, pass string) (string, error) {
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
	require.Contains(t, recorder.Body.String(), "token contains an invalid number of segments")
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

// TestAuthenticateWithCredentialRotation tests that authentication succeeds
// when a token is signed with the new secret during credential rotation.
// This is a regression test for GitHub issue #711.
func TestAuthenticateWithCredentialRotation(t *testing.T) {
	const (
		user       = "testuser"
		oldSecret  = "!_?z$Tf$o}iDcJQ4Yk|&H87dm5#ZO'old"
		newSecret  = "!_?z$Tf$o}iDcJQ4Yk|&H87dm5#ZO'new"
	)

	t.Run("authenticate with old secret when NewData is present", func(t *testing.T) {
		jwt := &JWT{
			Users: map[string]UserData{
				user: {
					Password: "oldpassword12345!A",
					Secret:   oldSecret,
					Exp:      60,
					NewData: &UserData{
						Password: "newpassword12345!A",
						Secret:   newSecret,
						Exp:      60,
					},
				},
			},
		}

		// Generate token with old secret (primary credentials)
		token, err := jwt.GenerateToken(user, "oldpassword12345!A")
		require.NoError(t, err)

		// Authenticate should succeed with old secret
		authenticatedUser, err := jwt.Authenticate(user, token)
		require.NoError(t, err)
		require.Equal(t, user, authenticatedUser)
	})

	t.Run("authenticate with new secret when NewData is present (issue 711 fix)", func(t *testing.T) {
		jwt := &JWT{
			Users: map[string]UserData{
				user: {
					Password: "oldpassword12345!A",
					Secret:   oldSecret,
					Exp:      60,
					NewData: &UserData{
						Password: "newpassword12345!A",
						Secret:   newSecret,
						Exp:      60,
					},
				},
			},
		}

		// Generate token with new secret (NewData credentials)
		token, err := jwt.GenerateToken(user, "newpassword12345!A")
		require.NoError(t, err)

		// Authenticate should succeed by falling back to NewData.Secret
		// Before fix for issue 711, this would fail because the error from
		// first parse was returned even when second parse succeeded
		authenticatedUser, err := jwt.Authenticate(user, token)
		require.NoError(t, err, "authentication should succeed with NewData secret during credential rotation")
		require.Equal(t, user, authenticatedUser)
	})

	t.Run("authenticate fails with invalid secret", func(t *testing.T) {
		jwt := &JWT{
			Users: map[string]UserData{
				user: {
					Password: "oldpassword12345!A",
					Secret:   oldSecret,
					Exp:      60,
					NewData: &UserData{
						Password: "newpassword12345!A",
						Secret:   newSecret,
						Exp:      60,
					},
				},
			},
		}

		// Generate token with a completely different secret (neither old nor new)
		wrongSecretJwt := &JWT{
			Users: map[string]UserData{
				user: {
					Password: "wrongpassword12345!A",
					Secret:   "!_?z$Tf$o}iDcJQ4Yk|&H87dm5#WRONG",
					Exp:      60,
				},
			},
		}
		token, err := wrongSecretJwt.GenerateToken(user, "wrongpassword12345!A")
		require.NoError(t, err)

		// Authenticate should fail - token was signed with wrong secret
		_, err = jwt.Authenticate(user, token)
		require.Error(t, err)
	})

	t.Run("authenticate fails without NewData when primary secret is wrong", func(t *testing.T) {
		jwt := &JWT{
			Users: map[string]UserData{
				user: {
					Password: "oldpassword12345!A",
					Secret:   oldSecret,
					Exp:      60,
					// No NewData - no fallback available
				},
			},
		}

		// Generate token with a different secret
		wrongSecretJwt := &JWT{
			Users: map[string]UserData{
				user: {
					Password: "wrongpassword12345!A",
					Secret:   "!_?z$Tf$o}iDcJQ4Yk|&H87dm5#WRONG",
					Exp:      60,
				},
			},
		}
		token, err := wrongSecretJwt.GenerateToken(user, "wrongpassword12345!A")
		require.NoError(t, err)

		// Authenticate should fail - no fallback since NewData is nil
		_, err = jwt.Authenticate(user, token)
		require.Error(t, err)
	})
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
		pass   string
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
				pass:   "SecretSecretSecretSecretSecretS1#$",
				secret: "Secret1!Secret1!Secret1!Secret1",
			},
			expect: "secret should be at least 32 characters",
		},
		// No uppercase
		{
			name: "No uppercase",
			args: args{
				pass:   "SecretSecretSecretSecretSecretS1#$",
				secret: "secretsecretsecretsecretsecrets1",
			},
			expect: "secret should contain at least one uppercase character",
		},
		// No lowercase
		{
			name: "No lowercase",
			args: args{
				pass:   "SecretSecretSecretSecretSecretS1#$",
				secret: "SECRETSECRETSECRETSECRETSECRETS1",
			},
			expect: "secret should contain at least one lowercase character",
		},
		// No number
		{
			name: "No number",
			args: args{
				pass:   "SecretSecretSecretSecretSecretS1#$",
				secret: "SecretSecretSecretSecretSecretSe",
			},
			expect: "secret should contain at least one digit",
		},
		// No special character
		{
			name: "No special character",
			args: args{
				pass:   "SecretSecretSecretSecretSecretS1#$",
				secret: "SecretSecretSecretSecretSecretS1",
			},
			expect: "secret should contain at least one special character",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := validateSecretAndPass([]string{tt.args.pass, tt.args.secret})
			require.Equal(t, tt.expect, actual.Error())
		})
	}
}

func TestJWT_CheckUpdatenewCred(t *testing.T) {
	now := time.Now().UTC()
	desiredTime := now.Add(time.Minute * 1)
	desiredTimeStr := desiredTime.Format("2006-01-02 15:04:05")
	fmt.Println(desiredTimeStr)
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
						Password:   "SecretSecretSecretSecretSecretS1#$",
						Secret:     secret,
						Exp:        1,
						OldCredExp: desiredTimeStr,
						NewData: &UserData{
							Password: "SecretSecretSecretSecretSecretS1#$x",
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
			err := a.CheckUpdateNewCred()
			require.NoError(t, err)
			d, ret := a.GetUserData("user")
			require.True(t, ret)
			require.Equal(t, tt.fields.Users["user"].Password, d.Password)
			require.Equal(t, secret, d.Secret)

			time.Sleep(time.Minute + time.Second)

			d, ret = a.GetUserData("user")
			require.True(t, ret)
			require.True(t, ret)
			require.Equal(t, "SecretSecretSecretSecretSecretS1#$x", d.Password)
			require.Equal(t, secret+"1", d.Secret)
		})
	}
}
