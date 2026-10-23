package authservice

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// OIDCClient handles interactions with Keycloak OIDC provider.
type OIDCClient struct {
	issuerURL    string
	clientID     string
	clientSecret string
	redirectURL  string
	httpClient   *http.Client
}

// UserClaims holds identity and role information extracted from Keycloak token.
type UserClaims struct {
	Subject           string `json:"sub"`
	Email             string `json:"email"`
	PreferredUsername string `json:"preferred_username"`
	Name              string `json:"name"`
	GivenName         string `json:"given_name"`
	FamilyName        string `json:"family_name"`
	Roles             []string
}

// NewOIDCClient creates a new OIDCClient.
func NewOIDCClient(issuerURL, clientID, clientSecret, redirectURL string) *OIDCClient {
	tr := &http.Transport{
		// #nosec G402
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // lab self-signed certs
	}
	return &OIDCClient{
		issuerURL:    strings.TrimRight(issuerURL, "/"),
		clientID:     clientID,
		clientSecret: clientSecret,
		redirectURL:  redirectURL,
		httpClient:   &http.Client{Transport: tr, Timeout: 15 * time.Second},
	}
}

// AuthURL returns the Keycloak login URL for initiating OIDC authorization code flow.
func (c *OIDCClient) AuthURL(state, nonce string) string {
	q := url.Values{}
	q.Set("client_id", c.clientID)
	q.Set("response_type", "code")
	q.Set("scope", "openid email profile")
	q.Set("redirect_uri", c.redirectURL)
	q.Set("state", state)
	if nonce != "" {
		q.Set("nonce", nonce)
	}
	return fmt.Sprintf("%s/protocol/openid-connect/auth?%s", c.issuerURL, q.Encode())
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// ExchangeCode exchanges an authorization code for tokens and extracts user claims.
func (c *OIDCClient) ExchangeCode(ctx context.Context, code string) (*UserClaims, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", c.clientID)
	data.Set("client_secret", c.clientSecret)
	data.Set("code", code)
	data.Set("redirect_uri", c.redirectURL)

	tokenURL := fmt.Sprintf("%s/protocol/openid-connect/token", c.issuerURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("exchange token: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token endpoint returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var tr tokenResponse
	if err := json.Unmarshal(bodyBytes, &tr); err != nil {
		return nil, fmt.Errorf("parse token response: %w", err)
	}

	// Prefer AccessToken for roles, or IDToken for profile claims
	claims, err := parseJWTClaims(tr.AccessToken)
	if err != nil {
		// Fallback to id token
		claims, err = parseJWTClaims(tr.IDToken)
		if err != nil {
			return nil, fmt.Errorf("parse jwt claims: %w", err)
		}
	}

	return claims, nil
}

// parseJWTClaims decodes unverified payload claims from a JWT string.
func parseJWTClaims(jwtStr string) (*UserClaims, error) {
	parts := strings.Split(jwtStr, ".")
	if len(parts) < 2 {
		return nil, errors.New("invalid jwt format")
	}

	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("base64 decode jwt payload: %w", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(payloadJSON, &raw); err != nil {
		return nil, fmt.Errorf("json unmarshal jwt payload: %w", err)
	}

	claims := &UserClaims{}
	if sub, ok := raw["sub"].(string); ok {
		claims.Subject = sub
	}
	if email, ok := raw["email"].(string); ok {
		claims.Email = email
	}
	if uname, ok := raw["preferred_username"].(string); ok {
		claims.PreferredUsername = uname
	}
	if name, ok := raw["name"].(string); ok {
		claims.Name = name
	}
	if gname, ok := raw["given_name"].(string); ok {
		claims.GivenName = gname
	}
	if fname, ok := raw["family_name"].(string); ok {
		claims.FamilyName = fname
	}

	// Extract client roles: resource_access[client_id].roles
	var roles []string
	if resAccess, ok := raw["resource_access"].(map[string]any); ok {
		for _, clientObj := range resAccess {
			if clientMap, ok := clientObj.(map[string]any); ok {
				if rList, ok := clientMap["roles"].([]any); ok {
					for _, r := range rList {
						if rStr, ok := r.(string); ok {
							roles = append(roles, rStr)
						}
					}
				}
			}
		}
	}
	// Extract realm roles: realm_access.roles
	if realmAccess, ok := raw["realm_access"].(map[string]any); ok {
		if rList, ok := realmAccess["roles"].([]any); ok {
			for _, r := range rList {
				if rStr, ok := r.(string); ok {
					roles = append(roles, rStr)
				}
			}
		}
	}
	claims.Roles = roles

	return claims, nil
}

// HasRole checks whether the user claims contain the specified role.
func (u *UserClaims) HasRole(roleName string) bool {
	for _, r := range u.Roles {
		if strings.EqualFold(r, roleName) {
			return true
		}
	}
	return false
}
