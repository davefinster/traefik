package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const apiBase = "https://api.tailscale.com/api/v2"

// api talks to the Tailscale control plane as the tailnet's own OAuth client.
// The tailnet is always addressed as "-", which an OAuth client scoped to one
// tailnet resolves to that tailnet.
type api struct {
	token string
	http  *http.Client
}

// newAPI exchanges an OAuth client credential for a bearer token.
func newAPI(ctx context.Context, clientID, clientSecret string) (*api, error) {
	form := url.Values{
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"grant_type":    {"client_credentials"},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		apiBase+"/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 30 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("requesting token: %w", err)
	}
	defer res.Body.Close()

	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		// The body of a failed token request echoes the client id but never
		// the secret, so it is safe to surface.
		return nil, fmt.Errorf("token request: %s: %s", res.Status, bytes.TrimSpace(body))
	}

	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("decoding token: %w", err)
	}
	if out.AccessToken == "" {
		return nil, fmt.Errorf("token response carried no access_token")
	}

	return &api{token: out.AccessToken, http: client}, nil
}

// do issues an authenticated request and decodes a JSON response into out,
// which may be nil when the response body is not wanted.
func (a *api) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		encoded, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, apiBase+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	res, err := a.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	raw, _ := io.ReadAll(res.Body)
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return &apiError{Status: res.StatusCode, Body: strings.TrimSpace(string(raw))}
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(raw, out)
}

type apiError struct {
	Status int
	Body   string
}

func (e *apiError) Error() string {
	return fmt.Sprintf("tailscale API %d: %s", e.Status, e.Body)
}

// protoPort is one entry of a VIP Service's advertised ports, in the string
// form the API takes ("tcp:443", "udp:5353", "*").
type protoPort string

// vipService is the control-plane definition of a Tailscale Service: its
// name and the ports it declares. A host must advertise at least these for
// control to consider it a valid host.
type vipService struct {
	Name    string      `json:"name"`
	Ports   []protoPort `json:"ports,omitempty"`
	Tags    []string    `json:"tags,omitempty"`
	Comment string      `json:"comment,omitempty"`
}

func (a *api) createService(ctx context.Context, svc vipService) error {
	return a.do(ctx, http.MethodPut, "/tailnet/-/vip-services/"+url.PathEscape(svc.Name), svc, nil)
}

func (a *api) getService(ctx context.Context, name string) (*vipService, error) {
	var out vipService
	if err := a.do(ctx, http.MethodGet, "/tailnet/-/vip-services/"+url.PathEscape(name), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (a *api) deleteService(ctx context.Context, name string) error {
	return a.do(ctx, http.MethodDelete, "/tailnet/-/vip-services/"+url.PathEscape(name), nil, nil)
}

// mintAuthKey creates an ephemeral, pre-authorized, reusable auth key
// carrying the given tags. Ephemeral so that a harness that dies without
// tearing down does not leave nodes behind.
func (a *api) mintAuthKey(ctx context.Context, tags []string) (string, error) {
	type caps struct {
		Devices struct {
			Create struct {
				Reusable      bool     `json:"reusable"`
				Ephemeral     bool     `json:"ephemeral"`
				Preauthorized bool     `json:"preauthorized"`
				Tags          []string `json:"tags"`
			} `json:"create"`
		} `json:"devices"`
	}

	var in struct {
		Capabilities  caps   `json:"capabilities"`
		ExpirySeconds int    `json:"expirySeconds"`
		Description   string `json:"description"`
	}
	in.Capabilities.Devices.Create.Reusable = true
	in.Capabilities.Devices.Create.Ephemeral = true
	in.Capabilities.Devices.Create.Preauthorized = true
	in.Capabilities.Devices.Create.Tags = tags
	in.ExpirySeconds = 3600
	in.Description = "traefik tailnet VIP harness (ephemeral, 1h)"

	var out struct {
		Key string `json:"key"`
	}
	if err := a.do(ctx, http.MethodPost, "/tailnet/-/keys", in, &out); err != nil {
		return "", err
	}
	if out.Key == "" {
		return "", fmt.Errorf("key response carried no key")
	}
	return out.Key, nil
}

// acl fetches the tailnet policy so the harness can report what is missing
// rather than editing a live policy itself.
func (a *api) acl(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/tailnet/-/acl", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	req.Header.Set("Accept", "application/hujson")

	res, err := a.http.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	raw, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		return "", &apiError{Status: res.StatusCode, Body: strings.TrimSpace(string(raw))}
	}
	return string(raw), nil
}
