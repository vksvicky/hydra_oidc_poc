package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/go-openapi/runtime/client"
	"github.com/gorilla/sessions"
	"github.com/knadh/koanf"
	jsonParser "github.com/knadh/koanf/parsers/json"
	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

type OpenIDConfiguration struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JwksUri               string `json:"jwks_uri"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
}

var (
	sessionStore *sessions.FilesystemStore
	k            = koanf.New(".")
)

const (
	sessionKeyAccessToken = iota
	sessionKeyRefreshToken
	sessionKeyIdToken
	sessionKeyUserId
	sessionKeyRoles
	sessionKeyEmail
	sessionKeyUsername
	sessionRedirectTarget
)

func main() {
	if err := k.Load(file.Provider("resourceapp.json"), jsonParser.Parser()); err != nil && !os.IsNotExist(err) {
		log.Fatalf("error loading config: %v", err)
	}
	const prefix = "RESOURCEAPP_"
	if err := k.Load(env.Provider(prefix, ".", func(s string) string {
		return strings.Replace(strings.ToLower(
			strings.TrimPrefix(s, prefix)), "_", ".", -1)
	}), nil); err != nil {
		log.Fatalf("error loading config: %v", err)
	}

	oidcServer := k.MustString("oidc.server")
	oidcClientId := k.MustString("oidc.client-id")
	oidcClientSecret := k.MustString("oidc.client-secret")

	sessionPath := k.MustString("session.path")
	sessionAuthKey, err := base64.StdEncoding.DecodeString(k.String("session.auth-key"))
	if err != nil {
		log.Fatalf("could not decode session auth key: %s", err)
	}
	sessionEncKey, err := base64.StdEncoding.DecodeString(k.String("session.enc-key"))
	if err != nil {
		log.Fatalf("could not decode session encryption key: %s", err)
	}

	generated := false
	if len(sessionAuthKey) != 64 {
		sessionAuthKey = generateKey(64)
		generated = true
	}
	if len(sessionEncKey) != 32 {
		sessionEncKey = generateKey(32)
		generated = true
	}

	if generated {
		_ = k.Load(confmap.Provider(map[string]interface{}{
			"session.auth-key": sessionAuthKey,
			"session.enc-key":  sessionEncKey,
		}, "."), nil)
		jsonData, err := k.Marshal(jsonParser.Parser())
		if err != nil {
			log.Fatalf("could not encode session config")
		}
		log.Infof("put the following in your resourceapp.json:\n%s", string(jsonData))
	}

	var discoveryResponse OpenIDConfiguration
	var discoveryUrl *url.URL

	if discoveryUrl, err = url.Parse(oidcServer); err != nil {
		log.Fatalf("could not parse oidc.server parameter value %s: %s", oidcServer, err)
	} else {
		discoveryUrl.Path = "/.well-known/openid-configuration"
	}
	apiClient, err := client.TLSClient(client.TLSClientOptions{InsecureSkipVerify: true})
	if err := discoverOidc(discoveryUrl, apiClient, &discoveryResponse); err != nil {
		log.Fatalf("OpenID Connect discovery failed: %s", err)
	}
	oauth2Config := &oauth2.Config{
		ClientID:     oidcClientId,
		ClientSecret: oidcClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  discoveryResponse.AuthorizationEndpoint,
			TokenURL: discoveryResponse.TokenEndpoint,
		},
		Scopes: []string{"openid", "offline"},
	}
	keySet, err := jwk.FetchHTTP(discoveryResponse.JwksUri, jwk.WithHTTPClient(apiClient))
	if err != nil {
		log.Fatalf("could not fetch JWKs: %s", err)
	}

	if _, err = os.Stat(sessionPath); err != nil {
		if os.IsNotExist(err) {
			if err = os.MkdirAll(sessionPath, 0700); err != nil {
				log.Fatalf("could not create session store directory: %s", err)
			}
		}
	}
	sessionStore = sessions.NewFilesystemStore(sessionPath, sessionAuthKey, sessionEncKey)

	http.Handle("/", authenticate(oauth2Config)(NewIndexPage(discoveryResponse.EndSessionEndpoint)))
	http.Handle("/callback", NewCallbackHandler(keySet, oauth2Config))

	err = http.ListenAndServe(":4000", http.DefaultServeMux)
	if err != nil {
		log.Fatal(err)
	}
}

func generateKey(length int) []byte {
	key := make([]byte, length)
	read, err := rand.Read(key)
	if err != nil {
		log.Fatalf("could not generate key: %s", err)
	}
	if read != length {
		log.Fatalf("read %d bytes, expected %d bytes", read, length)
	}
	return key
}

func discoverOidc(discoveryUrl *url.URL, apiClient *http.Client, o *OpenIDConfiguration) error {
	var body []byte
	req, err := http.NewRequest(http.MethodGet, discoveryUrl.String(), bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	req.Header = map[string][]string{
		"Accept": {"application/json"},
	}

	resp, err := apiClient.Do(req)
	if err != nil {
		return err
	}

	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(o)
	if err != nil {
		return err
	}

	return nil
}

type callbackHandler struct {
	keySet       *jwk.Set
	oauth2Config *oauth2.Config
}

func (c *callbackHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		http.Error(writer, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	if request.URL.Path != "/callback" {
		http.NotFound(writer, request)
		return
	}

	code := request.URL.Query().Get("code")

	ctx := context.Background()
	httpClient, err := client.TLSClient(client.TLSClientOptions{InsecureSkipVerify: true})
	ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)

	tok, err := c.oauth2Config.Exchange(ctx, code)
	if err != nil {
		log.Error(err)
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	session, err := sessionStore.Get(request, "resource_session")
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}

	session.Values[sessionKeyAccessToken] = tok.AccessToken
	session.Values[sessionKeyRefreshToken] = tok.RefreshToken
	session.Values[sessionKeyIdToken] = tok.Extra("id_token").(string)

	idToken := tok.Extra("id_token")
	if parsedIdToken, err := jwt.ParseString(idToken.(string), jwt.WithKeySet(c.keySet), jwt.WithOpenIDClaims()); err != nil {
		log.Error(err)
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	} else {
		log.Infof(`
ID Token
========

Subject:          %s
Audience:         %s
Issued at:        %s
Issued by:        %s
Not valid before: %s
Not valid after:  %s

`,
			parsedIdToken.Subject(),
			parsedIdToken.Audience(),
			parsedIdToken.IssuedAt(),
			parsedIdToken.Issuer(),
			parsedIdToken.NotBefore(),
			parsedIdToken.Expiration(),
		)

		session.Values[sessionKeyUserId] = parsedIdToken.Subject()

		if roles, ok := parsedIdToken.Get("Groups"); ok {
			session.Values[sessionKeyRoles] = roles
		}
		if username, ok := parsedIdToken.Get("Username"); ok {
			session.Values[sessionKeyUsername] = username
		}
		if email, ok := parsedIdToken.Get("Email"); ok {
			session.Values[sessionKeyEmail] = email
		}
	}
	if err = session.Save(request, writer); err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
	}
	if redirectTarget, ok := session.Values[sessionRedirectTarget]; ok {
		writer.Header().Set("Location", redirectTarget.(string))
	} else {
		writer.Header().Set("Location", "/")
	}

	writer.WriteHeader(http.StatusFound)
}

func NewCallbackHandler(keySet *jwk.Set, oauth2Config *oauth2.Config) *callbackHandler {
	return &callbackHandler{keySet: keySet, oauth2Config: oauth2Config}
}

func authenticate(oauth2Config *oauth2.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			session, err := sessionStore.Get(r, "resource_session")
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if _, ok := session.Values[sessionKeyUserId]; ok {
				next.ServeHTTP(w, r)
				return
			}
			session.Values[sessionRedirectTarget] = r.URL.String()
			if err = session.Save(r, w); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			var authUrl *url.URL
			if authUrl, err = url.Parse(oauth2Config.Endpoint.AuthURL); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			queryValues := authUrl.Query()
			queryValues.Set("client_id", k.String("oidc.client-id"))
			queryValues.Set("response_type", "code")
			queryValues.Set("scope", "openid offline")
			queryValues.Set("state", base64.URLEncoding.EncodeToString(generateKey(8)))
			authUrl.RawQuery = queryValues.Encode()

			w.Header().Set("Location", authUrl.String())
			w.WriteHeader(http.StatusFound)
		})
	}
}

type indexHandler struct {
	logoutUrl string
}

func (i indexHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		http.Error(writer, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	if request.URL.Path != "/" {
		http.NotFound(writer, request)
		return
	}
	writer.WriteHeader(http.StatusOK)

	page, err := template.New("").Parse(`
<!DOCTYPE html>
<html lang="en">
<head><title>Auth test</title></head>
<body>
<h1>Hello {{ .User }}</h1>
<p>This is an authorization protected resource</p>
<a href="{{ .LogoutURL }}">Logout</a>
</body>
</html>
`)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}
	session, err := sessionStore.Get(request, "resource_session")
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}

	logoutUrl, err := url.Parse(i.logoutUrl)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}
	var user string
	var ok bool
	if user, ok = session.Values[sessionKeyUsername].(string); ok {

	}
	if idToken, ok := session.Values[sessionKeyIdToken].(string); ok {
		logoutUrl.RawQuery = url.Values{
			"id_token_hint":            []string{idToken},
			"post_logout_redirect_uri": []string{"/logged_out"},
		}.Encode()
	}

	writer.Header().Add("Content-Type", "text/html")
	err = page.Execute(writer, map[string]interface{}{
		"User":      user,
		"LogoutURL": logoutUrl.String(),
	})
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}
}

func NewIndexPage(logoutUrl string) *indexHandler {
	return &indexHandler{logoutUrl: logoutUrl}
}
