package providers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	. "github.com/onsi/gomega"
)

const (
	dttSSOTestClientID = "redash-gate"
	// Shorter than 32 bytes, and contains characters golang.org/x/oauth2 would
	// URL-escape in Basic auth.
	dttSSOTestSecret = "s3cr+t/abc=="
)

// dttSSOTestServer mimics the SSO's token and check_token endpoints.
type dttSSOTestServer struct {
	*httptest.Server
	claims       map[string]interface{}
	signingKey   []byte
	lastForm     url.Values
	validTokens  map[string]bool
	tokenCounter int
}

func newDTTSSOTestServer() *dttSSOTestServer {
	s := &dttSSOTestServer{
		signingKey:  []byte(dttSSOTestSecret),
		validTokens: map[string]bool{},
	}
	s.Server = httptest.NewServer(http.HandlerFunc(s.handle))
	u, _ := url.Parse(s.URL)
	s.claims = map[string]interface{}{
		"iss":     "http://" + u.Host,
		"aud":     dttSSOTestClientID,
		"sub":     "0b5c1e1a-1111-2222-3333-444455556666",
		"user_id": "0b5c1e1a-1111-2222-3333-444455556666",
		"email":   "admin@example.com",
		"role":    "dtt_admin",
		"exp":     time.Now().Add(time.Hour).Unix(),
	}
	return s
}

func (s *dttSSOTestServer) handle(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/oauth/token":
		want := "Basic " + base64.StdEncoding.EncodeToString([]byte(dttSSOTestClientID+":"+dttSSOTestSecret))
		if r.Header.Get("Authorization") != want {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = r.ParseForm()
		s.lastForm = r.PostForm
		if r.PostForm.Get("grant_type") == "refresh_token" && !s.validTokens["refresh-"+r.PostForm.Get("refresh_token")] {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"Invalid refresh token"}`))
			return
		}
		s.tokenCounter++
		access := "access-" + string(rune('0'+s.tokenCounter))
		refresh := "refresh-" + string(rune('0'+s.tokenCounter))
		s.validTokens[access] = true
		s.validTokens["refresh-"+refresh] = true
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token":  access,
			"token_type":    "bearer",
			"expires_in":    3600,
			"refresh_token": refresh,
			"id_token":      s.idToken(),
			"scope":         "openid",
		})
	case "/oauth/check_token":
		token := r.Header.Get("Authorization")
		if len(token) > len("Bearer ") && s.validTokens[token[len("Bearer "):]] {
			_, _ = w.Write([]byte(`{"user_id":"0b5c1e1a-1111-2222-3333-444455556666","real_user_id":null,"issued_by":"redash-gate"}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("Invalid access token"))
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (s *dttSSOTestServer) idToken() string {
	if s.claims == nil {
		return ""
	}
	raw, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(s.claims)).SignedString(s.signingKey)
	if err != nil {
		panic(err)
	}
	return raw
}

func testDTTSSOProvider(server *dttSSOTestServer) *DTTSSOProvider {
	p := NewDTTSSOProvider(&ProviderData{ClientID: dttSSOTestClientID, ClientSecret: dttSSOTestSecret})
	u, _ := url.Parse(server.URL)
	updateURL(p.LoginURL, u.Host)
	updateURL(p.RedeemURL, u.Host)
	updateURL(p.ValidateURL, u.Host)
	return p
}

func TestNewDTTSSOProvider(t *testing.T) {
	g := NewWithT(t)

	providerData := NewDTTSSOProvider(&ProviderData{}).Data()
	g.Expect(providerData.ProviderName).To(Equal("DTT SSO"))
	g.Expect(providerData.LoginURL.String()).To(Equal("https://auth.thebestagent.pro/oauth/authorize"))
	g.Expect(providerData.RedeemURL.String()).To(Equal("https://auth.thebestagent.pro/oauth/token"))
	g.Expect(providerData.ValidateURL.String()).To(Equal("https://auth.thebestagent.pro/oauth/check_token"))
	g.Expect(providerData.Scope).To(Equal("openid"))
}

func TestDTTSSOProviderRedeem(t *testing.T) {
	g := NewWithT(t)
	server := newDTTSSOTestServer()
	defer server.Close()
	p := testDTTSSOProvider(server)

	s, err := p.Redeem(context.Background(), "https://redash.example.com/oauth2/callback", "the-code", "")
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(s.Email).To(Equal("admin@example.com"))
	g.Expect(s.User).To(Equal("0b5c1e1a-1111-2222-3333-444455556666"))
	g.Expect(s.Groups).To(Equal([]string{"dtt_admin"}))
	g.Expect(s.AccessToken).To(Equal("access-1"))
	g.Expect(s.RefreshToken).To(Equal("refresh-1"))
	g.Expect(s.IDToken).ToNot(BeEmpty())
	g.Expect(s.ExpiresOn).ToNot(BeNil())
	g.Expect(*s.ExpiresOn).To(BeTemporally("~", time.Now().Add(time.Hour), time.Minute))

	g.Expect(server.lastForm.Get("grant_type")).To(Equal("authorization_code"))
	g.Expect(server.lastForm.Get("code")).To(Equal("the-code"))
	g.Expect(server.lastForm.Get("redirect_uri")).To(Equal("https://redash.example.com/oauth2/callback"))
}

func TestDTTSSOProviderRedeemRejectsBadIDTokens(t *testing.T) {
	testCases := map[string]func(s *dttSSOTestServer){
		"signed with another secret": func(s *dttSSOTestServer) { s.signingKey = []byte("some-other-client-secret") },
		"other audience":             func(s *dttSSOTestServer) { s.claims["aud"] = "frappe-gate" },
		"other issuer":               func(s *dttSSOTestServer) { s.claims["iss"] = "https://evil.example.com" },
		"expired":                    func(s *dttSSOTestServer) { s.claims["exp"] = time.Now().Add(-time.Minute).Unix() },
		"no email":                   func(s *dttSSOTestServer) { delete(s.claims, "email") },
		"no id_token":                func(s *dttSSOTestServer) { s.claims = nil },
	}
	for name, tamper := range testCases {
		t.Run(name, func(t *testing.T) {
			g := NewWithT(t)
			server := newDTTSSOTestServer()
			defer server.Close()
			tamper(server)

			_, err := testDTTSSOProvider(server).Redeem(context.Background(), "https://redash.example.com/oauth2/callback", "the-code", "")
			g.Expect(err).To(HaveOccurred())
		})
	}
}

func TestDTTSSOProviderRedeemRejectsUnsignedIDToken(t *testing.T) {
	g := NewWithT(t)
	server := newDTTSSOTestServer()
	defer server.Close()
	p := testDTTSSOProvider(server)

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload, _ := json.Marshal(server.claims)
	unsigned := header + "." + base64.RawURLEncoding.EncodeToString(payload) + "."

	_, err := p.verifyIDToken(unsigned, dttSSOTestSecret)
	g.Expect(err).To(HaveOccurred())
}

func TestDTTSSOProviderRefreshSession(t *testing.T) {
	g := NewWithT(t)
	server := newDTTSSOTestServer()
	defer server.Close()
	p := testDTTSSOProvider(server)

	s, err := p.Redeem(context.Background(), "https://redash.example.com/oauth2/callback", "the-code", "")
	g.Expect(err).ToNot(HaveOccurred())
	nonce := []byte("keep-me")
	s.Nonce = nonce

	server.claims["role"] = "agent"
	server.claims["email"] = "renamed@example.com"
	refreshed, err := p.RefreshSession(context.Background(), s)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(refreshed).To(BeTrue())
	g.Expect(s.AccessToken).To(Equal("access-2"))
	g.Expect(s.RefreshToken).To(Equal("refresh-2"))
	g.Expect(s.Groups).To(Equal([]string{"agent"}))
	g.Expect(s.Email).To(Equal("renamed@example.com"))
	g.Expect(s.Nonce).To(Equal(nonce))
	g.Expect(server.lastForm.Get("grant_type")).To(Equal("refresh_token"))
	g.Expect(server.lastForm.Get("refresh_token")).To(Equal("refresh-1"))
}

func TestDTTSSOProviderRefreshSessionFailures(t *testing.T) {
	g := NewWithT(t)
	server := newDTTSSOTestServer()
	defer server.Close()
	p := testDTTSSOProvider(server)

	refreshed, err := p.RefreshSession(context.Background(), &sessions.SessionState{})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(refreshed).To(BeFalse())

	refreshed, err = p.RefreshSession(context.Background(), &sessions.SessionState{RefreshToken: "revoked"})
	g.Expect(err).To(HaveOccurred())
	g.Expect(refreshed).To(BeFalse())
}

func TestDTTSSOProviderValidateSession(t *testing.T) {
	g := NewWithT(t)
	server := newDTTSSOTestServer()
	defer server.Close()
	p := testDTTSSOProvider(server)

	s, err := p.Redeem(context.Background(), "https://redash.example.com/oauth2/callback", "the-code", "")
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(p.ValidateSession(context.Background(), s)).To(BeTrue())

	delete(server.validTokens, s.AccessToken)
	g.Expect(p.ValidateSession(context.Background(), s)).To(BeFalse())
}
