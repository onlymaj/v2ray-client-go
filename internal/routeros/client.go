package routeros

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Entry is one row of /ip/firewall/address-list. RouterOS returns every
// field as a string.
type Entry struct {
	ID      string `json:".id,omitempty"`
	List    string `json:"list"`
	Address string `json:"address"`
	Comment string `json:"comment,omitempty"`
	Dynamic string `json:"dynamic,omitempty"`
}

// Client is a minimal RouterOS v7 REST client for the IPv4 firewall
// address list.
type Client struct {
	base       string // e.g. https://172.17.0.1/rest
	user, pass string
	hc         *http.Client
}

// NewClient returns a client for the router at baseURL (scheme://host[:port],
// with or without a trailing /rest). insecure skips TLS verification, which
// RouterOS's default self-signed certificate needs.
func NewClient(baseURL, user, pass string, insecure bool) *Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: insecure}
	tr.MaxIdleConnsPerHost = 2
	return newClient(baseURL, user, pass, &http.Client{Transport: tr, Timeout: 10 * time.Second})
}

func newClient(baseURL, user, pass string, hc *http.Client) *Client {
	base := strings.TrimSuffix(strings.TrimRight(baseURL, "/"), "/rest")
	return &Client{base: base + "/rest", user: user, pass: pass, hc: hc}
}

// List returns the entries of address list name.
func (c *Client) List(ctx context.Context, name string) ([]Entry, error) {
	var all []Entry
	if err := c.do(ctx, http.MethodGet, "/ip/firewall/address-list?list="+url.QueryEscape(name), nil, &all); err != nil {
		return nil, err
	}
	out := all[:0]
	for _, e := range all { // the filter is server-side too, but be sure
		if e.List == name {
			out = append(out, e)
		}
	}
	return out, nil
}

// Add creates an entry. An "already have such entry" failure counts as
// success.
func (c *Client) Add(ctx context.Context, e Entry) error {
	e.ID, e.Dynamic = "", ""
	err := c.do(ctx, http.MethodPut, "/ip/firewall/address-list", e, nil)
	if err != nil && strings.Contains(err.Error(), "already have") {
		return nil
	}
	return err
}

// Remove deletes the entry with RouterOS id (e.g. "*1A").
func (c *Client) Remove(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/ip/firewall/address-list/"+url.PathEscape(id), nil, nil)
}

type apiError struct {
	Error   int    `json:"error"`
	Message string `json:"message"`
	Detail  string `json:"detail"`
}

func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.user, c.pass)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		var ae apiError
		if json.Unmarshal(b, &ae) == nil && (ae.Message != "" || ae.Detail != "") {
			return fmt.Errorf("routeros %s %s: %d %s: %s", method, path, resp.StatusCode, ae.Message, ae.Detail)
		}
		return fmt.Errorf("routeros %s %s: %s", method, path, resp.Status)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("routeros %s %s: decoding response: %w", method, path, err)
	}
	return nil
}
