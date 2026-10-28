package authservice

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Errors returned by DirectGrant.
var (
	// ErrBadCredentials means Keycloak refused the username, password or one-time code. Keycloak answers the same
	// invalid_grant for all three, so callers must not assume which one was wrong.
	ErrBadCredentials = errors.New("invalid credentials")
	// ErrAccessDenied means Keycloak refused the sign-in for a reason other than the credentials (policy, disabled client).
	ErrAccessDenied = errors.New("access denied")
)

// DirectGrant signs a user in with Keycloak's Resource Owner Password flow bound to the client (flow n8n-direct-grant).
// totp is sent only when non-empty; Keycloak enforces it for users that hold an OTP credential and the n8n-admin role.
func (c *OIDCClient) DirectGrant(ctx context.Context, username, password, totp string) (*UserClaims, error) {
	form := url.Values{
		"grant_type":    {"password"},
		"client_id":     {c.clientID},
		"client_secret": {c.clientSecret},
		"username":      {username},
		"password":      {password},
		"scope":         {"openid profile email"},
	}
	if totp != "" {
		form.Set("totp", totp)
	}
	status, body, err := c.formPost(ctx, c.issuerURL+"/protocol/openid-connect/token", form)
	if err != nil {
		return nil, fmt.Errorf("direct grant: %w", err)
	}
	if status != http.StatusOK {
		var e struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
		}
		_ = json.Unmarshal(body, &e)
		switch {
		case e.Error == "invalid_grant":
			return nil, ErrBadCredentials
		case status == http.StatusForbidden || e.Error == "access_denied" || e.Error == "unauthorized_client":
			return nil, ErrAccessDenied
		}
		return nil, fmt.Errorf("direct grant failed (%d): %s", status, e.Error)
	}
	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("direct grant response: %w", err)
	}
	claims, err := parseJWTClaims(tr.AccessToken)
	if err != nil {
		if claims, err = parseJWTClaims(tr.IDToken); err != nil {
			return nil, fmt.Errorf("parse jwt claims: %w", err)
		}
	}
	return claims, nil
}

func (c *OIDCClient) formPost(ctx context.Context, endpoint string, form url.Values) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, err
}

// keycloakAdmin talks to the Keycloak Admin API with the client's own service account (needs the realm-management
// roles view-users, manage-users and query-clients). It is how the one-time code credential becomes a native Keycloak
// credential, so Keycloak stays the only place that verifies it.
type keycloakAdmin struct {
	c *OIDCClient

	mu       sync.Mutex
	token    string
	tokenExp time.Time
	cliUUID  string
}

func newKeycloakAdmin(c *OIDCClient) *keycloakAdmin { return &keycloakAdmin{c: c} }

func (k *keycloakAdmin) base() (string, error) {
	i := strings.Index(k.c.issuerURL, "/realms/")
	if i < 0 {
		return "", errors.New("keycloak url is not a realm url")
	}
	return k.c.issuerURL[:i] + "/admin/realms/" + k.c.issuerURL[i+len("/realms/"):], nil
}

func (k *keycloakAdmin) serviceToken(ctx context.Context) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.token != "" && time.Now().Add(20*time.Second).Before(k.tokenExp) {
		return k.token, nil
	}
	status, body, err := k.c.formPost(ctx, k.c.issuerURL+"/protocol/openid-connect/token", url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {k.c.clientID},
		"client_secret": {k.c.clientSecret},
	})
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("service account token: status %d", status)
	}
	var tr struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tr); err != nil || tr.AccessToken == "" {
		return "", errors.New("service account token: bad response")
	}
	k.token = tr.AccessToken
	k.tokenExp = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	return k.token, nil
}

func (k *keycloakAdmin) do(ctx context.Context, method, path string, in, out any) (int, error) {
	base, err := k.base()
	if err != nil {
		return 0, err
	}
	tok, err := k.serviceToken(ctx)
	if err != nil {
		return 0, err
	}
	var rd io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return 0, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path, rd)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := k.c.httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return resp.StatusCode, err
	}
	if resp.StatusCode >= 300 {
		return resp.StatusCode, fmt.Errorf("keycloak admin %s %s: status %d", method, strings.SplitN(path, "?", 2)[0], resp.StatusCode)
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return resp.StatusCode, err
		}
	}
	return resp.StatusCode, nil
}

// HasOTP reports whether the user already holds an OTP credential in Keycloak.
func (k *keycloakAdmin) HasOTP(ctx context.Context, userID string) (bool, error) {
	var creds []struct {
		Type string `json:"type"`
	}
	if _, err := k.do(ctx, http.MethodGet, "/users/"+url.PathEscape(userID)+"/credentials", nil, &creds); err != nil {
		return false, err
	}
	for _, c := range creds {
		if c.Type == "otp" {
			return true, nil
		}
	}
	return false, nil
}

// clientUUID resolves the internal id of the OIDC client (cached).
func (k *keycloakAdmin) clientUUID(ctx context.Context) (string, error) {
	k.mu.Lock()
	id := k.cliUUID
	k.mu.Unlock()
	if id != "" {
		return id, nil
	}
	var cs []struct {
		ID string `json:"id"`
	}
	if _, err := k.do(ctx, http.MethodGet, "/clients?clientId="+url.QueryEscape(k.c.clientID), nil, &cs); err != nil {
		return "", err
	}
	if len(cs) == 0 {
		return "", errors.New("keycloak client not found")
	}
	k.mu.Lock()
	k.cliUUID = cs[0].ID
	k.mu.Unlock()
	return cs[0].ID, nil
}

// OTPRequiredFor reports whether the login name (username or email) belongs to a user who must present a one-time
// code: holds an OTP credential and the n8n-admin client role (the condition of the Keycloak flow). It exists only to
// tell the sign-in page to ask for the code, because Keycloak answers invalid_grant both for a wrong password and for
// a missing code.
func (k *keycloakAdmin) OTPRequiredFor(ctx context.Context, login, adminRole string) (bool, error) {
	var users []struct {
		ID string `json:"id"`
	}
	for _, q := range []string{"username", "email"} {
		users = nil
		if _, err := k.do(ctx, http.MethodGet, "/users?"+q+"="+url.QueryEscape(login)+"&exact=true", nil, &users); err != nil {
			return false, err
		}
		if len(users) == 1 {
			break
		}
	}
	if len(users) != 1 {
		return false, nil
	}
	has, err := k.HasOTP(ctx, users[0].ID)
	if err != nil || !has {
		return false, err
	}
	cid, err := k.clientUUID(ctx)
	if err != nil {
		return false, err
	}
	var roles []struct {
		Name string `json:"name"`
	}
	if _, err := k.do(ctx, http.MethodGet, "/users/"+users[0].ID+"/role-mappings/clients/"+cid+"/composite", nil, &roles); err != nil {
		return false, err
	}
	for _, r := range roles {
		if strings.EqualFold(r.Name, adminRole) {
			return true, nil
		}
	}
	return false, nil
}

// RegisterOTP stores secret (the raw secret string, not its base32 form) as the user's OTP credential. It refuses to
// replace an existing OTP credential, so enrolment can never overwrite someone's authenticator.
func (k *keycloakAdmin) RegisterOTP(ctx context.Context, userID, secret string) error {
	has, err := k.HasOTP(ctx, userID)
	if err != nil {
		return err
	}
	if has {
		return errOTPExists
	}
	var rep map[string]any
	if _, err := k.do(ctx, http.MethodGet, "/users/"+url.PathEscape(userID), nil, &rep); err != nil {
		return err
	}
	secretData, _ := json.Marshal(map[string]string{"value": secret})
	credData, _ := json.Marshal(map[string]any{"subType": "totp", "digits": 6, "period": 30, "algorithm": "HmacSHA1", "counter": 0})
	rep["credentials"] = []map[string]any{{
		"type":           "otp",
		"userLabel":      "Authenticator",
		"secretData":     string(secretData),
		"credentialData": string(credData),
	}}
	_, err = k.do(ctx, http.MethodPut, "/users/"+url.PathEscape(userID), rep, nil)
	return err
}

var errOTPExists = errors.New("otp credential already exists")
