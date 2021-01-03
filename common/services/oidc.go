package services

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/lestrrat-go/jwx/jwk"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"

	"git.cacert.org/oidc_login/common/models"
)

type oidcContextKey int

// context keys
const (
	ctxOidcConfig oidcContextKey = iota
	ctxOAuth2Config
	ctxOidcJwks
)

// Parameters for DiscoverOIDC
type OidcParams struct {
	OidcServer       string
	OidcClientId     string
	OidcClientSecret string
	APIClient        *http.Client
}

// Discover OpenID Connect parameters from the discovery endpoint and the
// JSON Web Key Set from the discovered jwksUri.
//
// The subset of values specified by models.OpenIDConfiguration is stored in
// the given context and can be retrieved from the context by GetOidcConfig.
//
// OAuth2 specific values are stored in another context object and can be
// retrieved by GetOAuth2Config.
//
// The JSON Web Key Set can be retrieved by GetJwkSet.
func DiscoverOIDC(ctx context.Context, logger *log.Logger, params *OidcParams) (context.Context, error) {
	var discoveryUrl *url.URL

	discoveryUrl, err := url.Parse(params.OidcServer)
	if err != nil {
		logger.Fatalf("could not parse oidc.server parameter value %s: %s", params.OidcServer, err)
	} else {
		discoveryUrl.Path = "/.well-known/openid-configuration"
	}

	var body []byte
	var req *http.Request
	req, err = http.NewRequest(http.MethodGet, discoveryUrl.String(), bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	req.Header = map[string][]string{
		"Accept": {"application/json"},
	}

	resp, err := params.APIClient.Do(req)
	if err != nil {
		return nil, err
	}

	dec := json.NewDecoder(resp.Body)
	discoveryResponse := &models.OpenIDConfiguration{}
	err = dec.Decode(discoveryResponse)
	if err != nil {
		return nil, err
	}
	ctx = context.WithValue(ctx, ctxOidcConfig, discoveryResponse)

	oauth2Config := &oauth2.Config{
		ClientID:     params.OidcClientId,
		ClientSecret: params.OidcClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  discoveryResponse.AuthorizationEndpoint,
			TokenURL: discoveryResponse.TokenEndpoint,
		},
		Scopes: []string{"openid", "offline"},
	}
	ctx = context.WithValue(ctx, ctxOAuth2Config, oauth2Config)

	keySet, err := jwk.FetchHTTP(discoveryResponse.JwksUri, jwk.WithHTTPClient(params.APIClient))
	if err != nil {
		log.Fatalf("could not fetch JWKs: %s", err)
	}
	ctx = context.WithValue(ctx, ctxOidcJwks, keySet)

	return ctx, nil
}

// Get the OpenID configuration from the context.
//
// DiscoverOIDC needs to be called before this is available.
func GetOidcConfig(ctx context.Context) *models.OpenIDConfiguration {
	return ctx.Value(ctxOidcConfig).(*models.OpenIDConfiguration)
}

// Get the OAuth 2 configuration configuration from the context.
//
// DiscoverOIDC needs to be called before this is available.
func GetOAuth2Config(ctx context.Context) *oauth2.Config {
	return ctx.Value(ctxOAuth2Config).(*oauth2.Config)
}

// Get the JSON Web Key set from the context.
//
// DiscoverOIDC needs to be called before this is available.
func GetJwkSet(ctx context.Context) *jwk.Set {
	return ctx.Value(ctxOidcJwks).(*jwk.Set)
}
