package middlewares

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestJWT_ScheduledRotationCompletes verifies that CheckUpdateNewCred takes
// the goroutine-scheduled path when OldCredExp is in the future, and that the
// rotation actually applies. No concurrent reader pressure here; this is
// purely about the rotation logic being correct.
func TestJWT_ScheduledRotationCompletes(t *testing.T) {
	const (
		user    = "scheduser"
		pass    = "SecretSecretSecretSecretSecretS1#$"
		secret1 = "!_?z$Tf$o}iDcJQ4Yk|&H87dm5#ZO'v1"
		pass2   = "SecretSecretSecretSecretSecretS2#$"
		secret2 = "!_?z$Tf$o}iDcJQ4Yk|&H87dm5#ZO'v2"
	)

	// +3s ensures we survive sub-second truncation from Format to second precision.
	expiry := time.Now().UTC().Add(3 * time.Second).Format("2006-01-02 15:04:05")

	j := &JWT{
		Users: map[string]UserData{
			user: {
				Password:   pass,
				Secret:     secret1,
				Exp:        60,
				OldCredExp: expiry,
				NewData: &UserData{
					Password: pass2,
					Secret:   secret2,
					Exp:      60,
				},
			},
		},
	}

	err := j.CheckUpdateNewCred()
	require.NoError(t, err)

	// Confirm we took the goroutine path: creds should still be originals.
	ud, ok := j.GetUserData(user)
	require.True(t, ok)
	require.Equal(t, pass, ud.Password, "should not have rotated immediately; goroutine path expected")

	// Poll for rotation completion.
	require.Eventually(t, func() bool {
		ud, ok := j.GetUserData(user)
		return ok && ud.Password == pass2
	}, 10*time.Second, 100*time.Millisecond, "credential rotation did not complete within timeout")

	// Verify full rotation state.
	ud, ok = j.GetUserData(user)
	require.True(t, ok)
	require.Equal(t, pass2, ud.Password)
	require.Equal(t, secret2, ud.Secret)
	require.Nil(t, ud.NewData, "NewData should be nil after rotation")
}
