package handlers

import (
	"context"
	"net/http"

	"github.com/go-openapi/runtime/client"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"

	"git.cacert.org/oidc_login/app/services"
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

type oidcCallbackHandler struct {
	keySet       *jwk.Set
	oauth2Config *oauth2.Config
}

func (c *oidcCallbackHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
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
		logrus.Error(err)
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	session, err := services.GetSessionStore().Get(request, "resource_session")
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}

	session.Values[sessionKeyAccessToken] = tok.AccessToken
	session.Values[sessionKeyRefreshToken] = tok.RefreshToken
	session.Values[sessionKeyIdToken] = tok.Extra("id_token").(string)

	idToken := tok.Extra("id_token")
	if parsedIdToken, err := jwt.ParseString(idToken.(string), jwt.WithKeySet(c.keySet), jwt.WithOpenIDClaims()); err != nil {
		logrus.Error(err)
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	} else {
		logrus.Infof(`
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

func NewCallbackHandler(keySet *jwk.Set, oauth2Config *oauth2.Config) *oidcCallbackHandler {
	return &oidcCallbackHandler{keySet: keySet, oauth2Config: oauth2Config}
}
