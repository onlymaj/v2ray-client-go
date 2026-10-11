package config

import (
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// Regression (round 6): overlapping Updates must never leave subscribers on
// an older snapshot than the store holds.
func TestStoreNotifiesLatestInOrder(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var applied int
	s.OnChange(func(c *Config) {
		time.Sleep(time.Millisecond) // widen the race window
		mu.Lock()
		applied = c.Settings.HealthInterval
		mu.Unlock()
	})
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(v int) {
			defer wg.Done()
			if err := s.Update(func(c *Config) error { c.Settings.HealthInterval = v; return nil }); err != nil {
				t.Error(err)
			}
		}(10 + i)
	}
	wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	if want := s.Get().Settings.HealthInterval; applied != want {
		t.Fatalf("subscriber applied %d, store holds %d", applied, want)
	}
}
