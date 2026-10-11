package api

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"testing"
	"time"
)

// Regression (round 5): an SSE stream must end once its session is logged
// out, not run on with the session checked only at open.
func TestSSEEndsAfterLogout(t *testing.T) {
	old := heartbeat
	heartbeat = 50 * time.Millisecond
	defer func() { heartbeat = old }()

	e := newEnv(t)
	e.login()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", e.srv.URL+"/api/events", nil)
	req.AddCookie(e.cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	br := bufio.NewReader(resp.Body)
	if _, err := br.ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	e.expect("POST", "/api/logout", nil, 204, nil)
	done := make(chan error, 1)
	go func() { _, err := io.Copy(io.Discard, br); done <- err }()
	select {
	case <-done: // stream closed by the server
	case <-time.After(2 * time.Second):
		t.Fatal("SSE stream still open after logout")
	}
}
