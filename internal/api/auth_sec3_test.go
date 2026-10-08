package api

import "testing"

func TestLogoutFromOtherIPKeepsSession(t *testing.T) {
	a, err := newAuth("pw")
	if err != nil {
		t.Fatal(err)
	}
	tok := a.newSession("192.168.88.10")
	a.drop(sessionReq(tok, "192.168.88.11:5000"))
	if !a.valid(sessionReq(tok, "192.168.88.10:5000")) {
		t.Fatal("a stolen cookie from another IP revoked the owner's session")
	}
	a.drop(sessionReq(tok, "192.168.88.10:6000"))
	if a.valid(sessionReq(tok, "192.168.88.10:5000")) {
		t.Fatal("logout from the session's IP did not revoke it")
	}
}
