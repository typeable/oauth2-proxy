package providers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	. "github.com/onsi/gomega"
)

func testAtlassianBackend(status int, body string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/me" || r.Header.Get("Authorization") != "Bearer imaginary_access_token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
}

func testAtlassianProvider(backend *httptest.Server) *AtlassianProvider {
	p := NewAtlassianProvider(&ProviderData{})
	u, _ := url.Parse(backend.URL)
	updateURL(p.ProfileURL, u.Host)
	updateURL(p.ValidateURL, u.Host)
	return p
}

func TestNewAtlassianProvider(t *testing.T) {
	g := NewWithT(t)

	providerData := NewAtlassianProvider(&ProviderData{}).Data()
	g.Expect(providerData.ProviderName).To(Equal("Atlassian"))
	g.Expect(providerData.LoginURL.String()).To(Equal("https://auth.atlassian.com/authorize"))
	g.Expect(providerData.RedeemURL.String()).To(Equal("https://auth.atlassian.com/oauth/token"))
	g.Expect(providerData.ProfileURL.String()).To(Equal("https://api.atlassian.com/me"))
	g.Expect(providerData.ValidateURL.String()).To(Equal("https://api.atlassian.com/me"))
	g.Expect(providerData.Scope).To(Equal("read:me"))
}

func TestAtlassianProviderGetLoginURL(t *testing.T) {
	g := NewWithT(t)
	p := NewAtlassianProvider(&ProviderData{ClientID: "client"})

	loginURL, err := url.Parse(p.GetLoginURL("https://proxy/oauth2/callback", "state", "",
		url.Values{"approval_prompt": {"force"}}))
	g.Expect(err).ToNot(HaveOccurred())

	q := loginURL.Query()
	g.Expect(q.Get("audience")).To(Equal("api.atlassian.com"))
	g.Expect(q.Get("prompt")).To(Equal("consent"))
	g.Expect(q.Has("approval_prompt")).To(BeFalse())
	g.Expect(q.Get("scope")).To(Equal("read:me"))

	loginURL, err = url.Parse(p.GetLoginURL("https://proxy/oauth2/callback", "state", "",
		url.Values{"prompt": {"login"}}))
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(loginURL.Query().Get("prompt")).To(Equal("login"))
}

func TestAtlassianProviderEnrichSession(t *testing.T) {
	g := NewWithT(t)
	b := testAtlassianBackend(http.StatusOK, `{"account_id":"abc","email":"user@example.com"}`)
	defer b.Close()
	p := testAtlassianProvider(b)

	session := CreateAuthorizedSession()
	g.Expect(p.EnrichSession(context.Background(), session)).To(Succeed())
	g.Expect(session.Email).To(Equal("user@example.com"))
}

func TestAtlassianProviderEnrichSessionWithoutEmail(t *testing.T) {
	g := NewWithT(t)
	b := testAtlassianBackend(http.StatusOK, `{"account_id":"abc"}`)
	defer b.Close()
	p := testAtlassianProvider(b)

	g.Expect(p.EnrichSession(context.Background(), CreateAuthorizedSession())).ToNot(Succeed())
}

func TestAtlassianProviderValidateSession(t *testing.T) {
	g := NewWithT(t)
	b := testAtlassianBackend(http.StatusOK, `{"email":"user@example.com"}`)
	defer b.Close()
	p := testAtlassianProvider(b)

	g.Expect(p.ValidateSession(context.Background(), CreateAuthorizedSession())).To(BeTrue())
	g.Expect(p.ValidateSession(context.Background(), &sessions.SessionState{AccessToken: "wrong"})).To(BeFalse())
}
