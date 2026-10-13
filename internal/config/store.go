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
	"strings"
	"sync"

	"github.com/onlymaj/v2ray-client-go/internal/group"
	"github.com/onlymaj/v2ray-client-go/internal/router"
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

// MaxFileSize bounds config.json. Every save clones the config through
// JSON, validates it and encodes it again, and each part that uses it keeps
// its own structures: a config of 3 MiB cost 10 to 15 MiB on every save and
// 8 MiB for each list the UI asked for (round 21). 1000 ordinary clients
// are under half of this.
const MaxFileSize = 1 << 20

// ErrTooLarge is returned by Update when the config would not fit.
var ErrTooLarge = errors.New("the configuration is too large")

// tmpPattern names the temporary file of a save.
const tmpPattern = ".config-*.json"

// Open loads path, or starts from Default() if it doesn't exist yet.
func Open(path string) (*Store, error) {
	s := &Store{path: path}
	// What a save that was cut short (power loss) left behind; each can be
	// as large as the config, on a small flash (round 19).
	// Only names os.CreateTemp makes from tmpPattern (digits in place of
	// the star): the directory is the admin's mount and may hold a
	// ".config-backup.json" of theirs (round 20).
	dir := filepath.Dir(path)
	if ents, err := os.ReadDir(dir); err == nil {
		pre, suf, _ := strings.Cut(tmpPattern, "*")
		for _, e := range ents {
			mid, ok := strings.CutPrefix(e.Name(), pre)
			mid, ok2 := strings.CutSuffix(mid, suf)
			if ok && ok2 && mid != "" && strings.Trim(mid, "0123456789") == "" && e.Type().IsRegular() {
				os.Remove(filepath.Join(dir, e.Name()))
			}
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
	// Only the settings start from the defaults, for fields the file does
	// not have. Decoding into Default() merged the file's first rule into
	// the default rule, and a first rule to "direct" or "block" came back
	// with the default rule's target id (round 22).
	def := Default()
	c := &Config{Settings: def.Settings}
	if err := json.Unmarshal(data, c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if c.Clients == nil {
		c.Clients = def.Clients
	}
	if c.Groups == nil {
		c.Groups = def.Groups
	}
	if c.Rules == nil {
		c.Rules = def.Rules
	}
	if c.Subscriptions == nil {
		c.Subscriptions = def.Subscriptions
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
	if err := s.replace(fn); err != nil {
		if err == errUnchanged {
			return nil
		}
		return err
	}

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

// replace is the locked part of Update. The lock is released by defer: a
// panic in fn would otherwise leave it held and every later request
// waiting on Get (round 23).
func (s *Store) replace(fn func(*Config) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	before, err := marshal(s.cur, "")
	if err != nil {
		return err
	}
	next := &Config{}
	if err := json.Unmarshal(before, next); err != nil {
		return err
	}
	if err := fn(next); err != nil {
		return err
	}
	// Never null in the file: Open takes a missing list for "use the
	// default", so rules saved as null came back as the default rule
	// after a restart, or stopped it (round 23).
	if next.Clients == nil {
		next.Clients = []Client{}
	}
	if next.Groups == nil {
		next.Groups = []group.Group{}
	}
	if next.Rules == nil {
		next.Rules = []router.Rule{}
	}
	if next.Subscriptions == nil {
		next.Subscriptions = []Subscription{}
	}
	if err := next.Validate(); err != nil {
		return err
	}
	// Disk is written only when the config changes: a save of what is
	// there already (an import of known links, the settings form sent
	// unchanged) rewrote the file and made every component reload, with a
	// DNS cache flush and a new lookup of every server name (round 26).
	if after, err := marshal(next, ""); err == nil && bytes.Equal(after, before) {
		return errUnchanged
	}
	if err := s.write(next); err != nil {
		return err
	}
	s.cur = next
	return nil
}

var errUnchanged = errors.New("config: unchanged")

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
	if len(data) > MaxFileSize {
		return fmt.Errorf("%w: %d KiB, the limit is %d KiB; remove clients, rules or a subscription", ErrTooLarge, len(data)>>10, MaxFileSize>>10)
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
	if err := os.Rename(tmp.Name(), s.path); err != nil {
		return err
	}
	// Make the rename last through a power cut, so a save the UI confirmed
	// is not undone. Not every filesystem can sync a directory; the save
	// has happened either way.
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
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
