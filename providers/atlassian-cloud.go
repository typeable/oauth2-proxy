package providers

import (
	"context"
	"errors"
	"net/url"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
)

// AtlassianProvider represents an Atlassian Cloud based Identity Provider
type AtlassianProvider struct {
	*ProviderData
}

var _ Provider = (*AtlassianProvider)(nil)

const (
	atlassianProviderName = "Atlassian"
	atlassianDefaultScope = "read:me"
	atlassianPrompt       = "consent"
	atlassianAudience     = "api.atlassian.com"
)

var (
	atlassianDefaultLoginURL = &url.URL{
		Scheme: "https",
		Host:   "auth.atlassian.com",
		Path:   "/authorize",
	}

	atlassianDefaultRedeemURL = &url.URL{
		Scheme: "https",
		Host:   "auth.atlassian.com",
		Path:   "/oauth/token",
	}

	// atlassianDefaultProfileURL returns the signed-in user's profile.
	atlassianDefaultProfileURL = &url.URL{
		Scheme: "https",
		Host:   "api.atlassian.com",
		Path:   "/me",
	}
)

// NewAtlassianProvider initiates a new AtlassianProvider
func NewAtlassianProvider(p *ProviderData) *AtlassianProvider {
	p.setProviderDefaults(providerDefaults{
		name:        atlassianProviderName,
		loginURL:    atlassianDefaultLoginURL,
		redeemURL:   atlassianDefaultRedeemURL,
		profileURL:  atlassianDefaultProfileURL,
		validateURL: atlassianDefaultProfileURL,
		scope:       atlassianDefaultScope,
	})
	return &AtlassianProvider{ProviderData: p}
}

// GetLoginURL adds the audience and prompt parameters Atlassian requires.
func (p *AtlassianProvider) GetLoginURL(redirectURI, state, _ string, extraParams url.Values) string {
	params := url.Values{}
	for k, v := range extraParams {
		params[k] = v
	}
	params.Del("approval_prompt")
	if params.Get("prompt") == "" {
		params.Set("prompt", atlassianPrompt)
	}
	params.Set("audience", atlassianAudience)

	loginURL := makeLoginURL(p.ProviderData, redirectURI, state, params)
	return loginURL.String()
}

// EnrichSession sets the session's email from the Atlassian profile.
func (p *AtlassianProvider) EnrichSession(ctx context.Context, s *sessions.SessionState) error {
	var profile struct {
		Email string `json:"email"`
	}
	err := requests.New(p.ProfileURL.String()).
		WithContext(ctx).
		WithHeaders(makeOIDCHeader(s.AccessToken)).
		Do().
		UnmarshalInto(&profile)
	if err != nil {
		return err
	}
	if profile.Email == "" {
		return errors.New("no email in Atlassian profile")
	}
	s.Email = profile.Email
	return nil
}

// ValidateSession validates the AccessToken
func (p *AtlassianProvider) ValidateSession(ctx context.Context, s *sessions.SessionState) bool {
	return validateToken(ctx, p, s.AccessToken, makeOIDCHeader(s.AccessToken))
}
