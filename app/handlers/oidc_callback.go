package handlers

import (
	"context"
	"net/http"

	"github.com/go-openapi/runtime/client"
	"github.com/lestrrat-go/jwx/jwk"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"

	"git.cacert.org/oidc_login/app/services"
)

const (
	sessionKeyAccessToken = iota
	sessionKeyRefreshToken
	sessionKeyIdToken
	sessionRedirectTarget
)

type oidcCallbackHandler struct {
	keySet       *jwk.Set
	oauth2Config *oauth2.Config
}

func (c *oidcCallbackHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	if r.URL.Path != "/callback" {
		http.NotFound(w, r)
		return
	}

	errorText := r.URL.Query().Get("error")
	errorDescription := r.URL.Query().Get("error_description")
	if errorText != "" {
		c.RenderErrorTemplate(w, r, errorText, errorDescription)
		return
	}

	code := r.URL.Query().Get("code")

	ctx := context.Background()
	httpClient, err := client.TLSClient(client.TLSClientOptions{InsecureSkipVerify: true})
	ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)

	tok, err := c.oauth2Config.Exchange(ctx, code)
	if err != nil {
		log.Error(err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	session, err := services.GetSessionStore().Get(r, "resource_session")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	session.Values[sessionKeyAccessToken] = tok.AccessToken
	session.Values[sessionKeyRefreshToken] = tok.RefreshToken

	idToken := tok.Extra("id_token").(string)
	session.Values[sessionKeyIdToken] = idToken

	if oidcToken, err := ParseIdToken(idToken, c.keySet); err != nil {
		log.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
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
			oidcToken.Subject(),
			oidcToken.Audience(),
			oidcToken.IssuedAt(),
			oidcToken.Issuer(),
			oidcToken.NotBefore(),
			oidcToken.Expiration(),
		)
	}

	if err = session.Save(r, w); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	if redirectTarget, ok := session.Values[sessionRedirectTarget]; ok {
		w.Header().Set("Location", redirectTarget.(string))
	} else {
		w.Header().Set("Location", "/")
	}

	w.WriteHeader(http.StatusFound)
}

func (c *oidcCallbackHandler) RenderErrorTemplate(w http.ResponseWriter, r *http.Request, errorText string, errorDescription string) {
	if errorDescription != "" {
		http.Error(w, errorDescription, http.StatusForbidden)
	} else {
		http.Error(w, errorText, http.StatusForbidden)
	}
}

func NewCallbackHandler(keySet *jwk.Set, oauth2Config *oauth2.Config) *oidcCallbackHandler {
	return &oidcCallbackHandler{keySet: keySet, oauth2Config: oauth2Config}
}
