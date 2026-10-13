package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sync"
)

// Store owns the config. Readers get an immutable snapshot; writers go
// through Update, which validates, persists and notifies subscribers.
type Store struct {
	path string

	mu   sync.Mutex
	cur  *Config
	subs []func(*Config)

	notifyMu sync.Mutex // serializes subscriber calls
}

// tmpPattern names the temporary file of a save.
const tmpPattern = ".config-*.json"

// Open loads path, or starts from Default() if it doesn't exist yet.
func Open(path string) (*Store, error) {
	s := &Store{path: path}
	// What a save that was cut short (power loss) left behind; each can be
	// as large as the config, on a small flash (round 19).
	if old, _ := filepath.Glob(filepath.Join(filepath.Dir(path), tmpPattern)); len(old) > 0 {
		for _, f := range old {
			os.Remove(f)
		}
	}
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		s.cur = Default()
		return s, nil
	case err != nil:
		return nil, err
	}
	c := Default()
	if err := json.Unmarshal(data, c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	for _, msg := range c.Settings.repair() {
		log.Printf("config: %s", msg)
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	s.cur = c
	return s, nil
}

// Get returns the current snapshot. Callers must not modify it.
func (s *Store) Get() *Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cur
}

// Update runs fn on a deep copy, validates the result, writes it to disk
// and then publishes it. If fn or validation fails nothing changes.
func (s *Store) Update(fn func(*Config) error) error {
	s.mu.Lock()
	next, err := clone(s.cur)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	if err := fn(next); err != nil {
		s.mu.Unlock()
		return err
	}
	if err := next.Validate(); err != nil {
		s.mu.Unlock()
		return err
	}
	if err := s.write(next); err != nil {
		s.mu.Unlock()
		return err
	}
	s.cur = next
	s.mu.Unlock()

	// Notify one update at a time, always with the latest snapshot: two
	// overlapping Updates may reach this point in either order, and the last
	// notification must carry the newest config.
	s.notifyMu.Lock()
	defer s.notifyMu.Unlock()
	s.mu.Lock()
	cur := s.cur
	subs := append([]func(*Config){}, s.subs...)
	s.mu.Unlock()
	for _, f := range subs {
		f(cur)
	}
	return nil
}

// OnChange registers f to be called (synchronously, after the write) with
// every new snapshot.
func (s *Store) OnChange(f func(*Config)) {
	s.mu.Lock()
	s.subs = append(s.subs, f)
	s.mu.Unlock()
}

func (s *Store) write(c *Config) error {
	data, err := marshal(c, "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, tmpPattern)
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.path)
}

func clone(c *Config) (*Config, error) {
	data, err := marshal(c, "")
	if err != nil {
		return nil, err
	}
	out := &Config{}
	return out, json.Unmarshal(data, out)
}

// marshal encodes c without HTML escaping: encoding/json would write each
// '<', '>' and '&' as six bytes, so a subscription of names made of them
// became a config six times its size, rewritten on every save.
func marshal(c *Config, indent string) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", indent)
	if err := enc.Encode(c); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
