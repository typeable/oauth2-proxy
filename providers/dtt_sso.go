package providers

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
)

// DTTSSOProvider signs users in with the DTT SSO (auth-server).
type DTTSSOProvider struct {
	*ProviderData
}

var _ Provider = (*DTTSSOProvider)(nil)

const (
	dttSSOProviderName = "DTT SSO"
	dttSSODefaultScope = "openid"
)

var (
	dttSSODefaultLoginURL = &url.URL{
		Scheme: "https",
		Host:   "auth.thebestagent.pro",
		Path:   "/oauth/authorize",
	}

	dttSSODefaultRedeemURL = &url.URL{
		Scheme: "https",
		Host:   "auth.thebestagent.pro",
		Path:   "/oauth/token",
	}

	dttSSODefaultValidateURL = &url.URL{
		Scheme: "https",
		Host:   "auth.thebestagent.pro",
		Path:   "/oauth/check_token",
	}
)

// NewDTTSSOProvider initiates a new DTTSSOProvider
func NewDTTSSOProvider(p *ProviderData) *DTTSSOProvider {
	p.setProviderDefaults(providerDefaults{
		name:        dttSSOProviderName,
		loginURL:    dttSSODefaultLoginURL,
		redeemURL:   dttSSODefaultRedeemURL,
		profileURL:  nil,
		validateURL: dttSSODefaultValidateURL,
		scope:       dttSSODefaultScope,
	})
	return &DTTSSOProvider{ProviderData: p}
}

// dttSSOTokenResponse is the SSO's /oauth/token response.
type dttSSOTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	IDToken      string `json:"id_token"`
}

// dttSSOClaims holds the id_token claims the provider uses.
type dttSSOClaims struct {
	jwt.RegisteredClaims
	Email  string `json:"email"`
	Role   string `json:"role"`
	UserID string `json:"user_id"`
}

// Redeem exchanges the authorization code for a session.
func (p *DTTSSOProvider) Redeem(ctx context.Context, redirectURL, code, _ string) (*sessions.SessionState, error) {
	if code == "" {
		return nil, ErrMissingCode
	}
	return p.requestTokens(ctx, url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {redirectURL},
	})
}

// RefreshSession renews the tokens and re-reads the email and role.
func (p *DTTSSOProvider) RefreshSession(ctx context.Context, s *sessions.SessionState) (bool, error) {
	if s == nil || s.RefreshToken == "" {
		return false, nil
	}
	refreshed, err := p.requestTokens(ctx, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {s.RefreshToken},
	})
	if err != nil {
		return false, fmt.Errorf("unable to redeem refresh token: %v", err)
	}
	s.AccessToken = refreshed.AccessToken
	s.RefreshToken = refreshed.RefreshToken
	s.IDToken = refreshed.IDToken
	s.Email = refreshed.Email
	s.User = refreshed.User
	s.Groups = refreshed.Groups
	s.CreatedAt = refreshed.CreatedAt
	s.ExpiresOn = refreshed.ExpiresOn
	return true, nil
}

// ValidateSession checks the access token with the SSO's check_token endpoint.
func (p *DTTSSOProvider) ValidateSession(ctx context.Context, s *sessions.SessionState) bool {
	return validateToken(ctx, p, s.AccessToken, makeOIDCHeader(s.AccessToken))
}

// requestTokens calls the token endpoint and builds a session from the verified id_token.
//
// The SSO compares the Basic credentials byte for byte, so they are sent unescaped
// rather than through golang.org/x/oauth2, which URL-escapes them.
func (p *DTTSSOProvider) requestTokens(ctx context.Context, params url.Values) (*sessions.SessionState, error) {
	clientSecret, err := p.GetClientSecret()
	if err != nil {
		return nil, err
	}
	credentials := base64.StdEncoding.EncodeToString([]byte(p.ClientID + ":" + clientSecret))

	result := requests.New(p.RedeemURL.String()).
		WithContext(ctx).
		WithMethod(http.MethodPost).
		WithBody(bytes.NewBufferString(params.Encode())).
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		SetHeader("Authorization", "Basic "+credentials).
		Do()
	if result.Error() != nil {
		return nil, result.Error()
	}
	if result.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("token request failed: status %d - %s", result.StatusCode(), result.Body())
	}

	var token dttSSOTokenResponse
	if err := result.UnmarshalInto(&token); err != nil {
		return nil, err
	}
	if token.AccessToken == "" {
		return nil, errors.New("token response carried no access_token")
	}
	claims, err := p.verifyIDToken(token.IDToken, clientSecret)
	if err != nil {
		return nil, err
	}

	s := &sessions.SessionState{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		IDToken:      token.IDToken,
		Email:        claims.Email,
		User:         claims.UserID,
	}
	if claims.Role != "" {
		s.Groups = []string{claims.Role}
	}
	s.CreatedAtNow()
	if token.ExpiresIn > 0 {
		s.ExpiresIn(time.Duration(token.ExpiresIn) * time.Second)
	}
	return s, nil
}

// verifyIDToken checks the id_token's HS256 signature (keyed on the client secret),
// issuer, audience and expiry.
//
// go-jose is not used: it rejects HMAC keys under 32 bytes, and SSO client secrets
// can be shorter.
func (p *DTTSSOProvider) verifyIDToken(raw, clientSecret string) (*dttSSOClaims, error) {
	if raw == "" {
		return nil, errors.New("token response carried no id_token; the scope must be exactly \"openid\"")
	}
	var claims dttSSOClaims
	_, err := jwt.ParseWithClaims(raw, &claims,
		func(*jwt.Token) (any, error) { return []byte(clientSecret), nil },
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer(p.issuer()),
		jwt.WithAudience(p.ClientID),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, fmt.Errorf("verifying id_token: %v", err)
	}
	if claims.Email == "" {
		return nil, errors.New("id_token carries no email")
	}
	return &claims, nil
}

// issuer is the SSO's site host, the origin of the login URL.
func (p *DTTSSOProvider) issuer() string {
	return p.LoginURL.Scheme + "://" + p.LoginURL.Host
}
