//go:build race

package middlewares

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestJWT_ConcurrentMapAccess exercises the core data race on the Users map.
// GetUserData reads j.Users while SetNewCred writes to it. Without
// synchronization, the race detector flags this.
func TestJWT_ConcurrentMapAccess(t *testing.T) {
	const (
		user    = "raceuser"
		pass    = "SecretSecretSecretSecretSecretS1#$"
		secret1 = "!_?z$Tf$o}iDcJQ4Yk|&H87dm5#ZO'v1"
		pass2   = "SecretSecretSecretSecretSecretS2#$"
		secret2 = "!_?z$Tf$o}iDcJQ4Yk|&H87dm5#ZO'v2"
	)

	j := &JWT{
		Users: map[string]UserData{
			user: {
				Password: pass,
				Secret:   secret1,
				Exp:      60,
				NewData: &UserData{
					Password: pass2,
					Secret:   secret2,
					Exp:      60,
				},
			},
		},
	}

	start := make(chan struct{})
	var wg sync.WaitGroup

	// 2 readers
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for n := 0; n < 500; n++ {
				j.GetUserData(user)
			}
		}()
	}

	// 1 writer
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for n := 0; n < 500; n++ {
			j.SetNewCred(user)
		}
	}()

	close(start)
	wg.Wait()
}

// TestJWT_ScheduledRotationRace verifies that the goroutine spawned by
// CheckUpdateNewCred races with concurrent GetUserData calls. Bounded
// iterations with pacing spread reads across the rotation window so the
// race detector catches the unsynchronized write without hot-looping
// into a runtime map fatal.
func TestJWT_ScheduledRotationRace(t *testing.T) {
	const (
		user    = "schedrace"
		pass    = "SecretSecretSecretSecretSecretS1#$"
		secret1 = "!_?z$Tf$o}iDcJQ4Yk|&H87dm5#ZO'v1"
		pass2   = "SecretSecretSecretSecretSecretS2#$"
		secret2 = "!_?z$Tf$o}iDcJQ4Yk|&H87dm5#ZO'v2"
	)

	// +2s raw survives sub-second truncation from Format; gives ~1-2s
	// actual delay, which the paced readers span comfortably.
	expiry := time.Now().UTC().Add(2 * time.Second).Format("2006-01-02 15:04:05")

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

	// Bounded reads paced to span the rotation window (~3s total).
	// The scheduled write fires 1-2s in; any unsynchronized overlap
	// is enough for the race detector.
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < 150; n++ {
				j.GetUserData(user)
				time.Sleep(20 * time.Millisecond)
			}
		}()
	}

	wg.Wait()
}
