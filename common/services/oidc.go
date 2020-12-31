package services

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"

	log "github.com/sirupsen/logrus"
)

type OpenIDConfiguration struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JwksUri               string `json:"jwks_uri"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
}

func DiscoverOIDC(logger *log.Logger, oidcServer string, apiClient *http.Client) (o *OpenIDConfiguration, err error) {
	var discoveryUrl *url.URL

	if discoveryUrl, err = url.Parse(oidcServer); err != nil {
		logger.Fatalf("could not parse oidc.server parameter value %s: %s", oidcServer, err)
	} else {
		discoveryUrl.Path = "/.well-known/openid-configuration"
	}

	var body []byte
	var req *http.Request
	req, err = http.NewRequest(http.MethodGet, discoveryUrl.String(), bytes.NewBuffer(body))
	if err != nil {
		return
	}
	req.Header = map[string][]string{
		"Accept": {"application/json"},
	}

	resp, err := apiClient.Do(req)
	if err != nil {
		return
	}

	dec := json.NewDecoder(resp.Body)
	o = &OpenIDConfiguration{}
	err = dec.Decode(o)
	if err != nil {
		return
	}

	return
}
