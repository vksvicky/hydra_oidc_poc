package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	client2 "github.com/go-openapi/runtime/client"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"golang.org/x/oauth2"
)

var oauth2Config *oauth2.Config

type OpenIDConfiguration struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSUri               string `json:"jwks_uri"`
}

func main() {
	headers := map[string][]string{
		"Accept": {"application/json"},
	}

	var body []byte

	req, err := http.NewRequest(http.MethodGet, "https://localhost:4444/.well-known/openid-configuration", bytes.NewBuffer(body))
	if err != nil {
		log.Panic(err)
	}
	req.Header = headers

	client, err := client2.TLSClient(client2.TLSClientOptions{InsecureSkipVerify: true})
	if err != nil {
		log.Panic(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Panic(err)
	}

	dec := json.NewDecoder(resp.Body)
	discoveryResponse := &OpenIDConfiguration{}
	err = dec.Decode(discoveryResponse)
	if err != nil {
		log.Panic(err)
	}

	oauth2Config = &oauth2.Config{
		ClientID:     "local-test-app",
		ClientSecret: "uzvTqaCvUSBMd0aVjECmD-egAJ",
		Endpoint: oauth2.Endpoint{
			AuthURL:  discoveryResponse.AuthorizationEndpoint,
			TokenURL: discoveryResponse.TokenEndpoint,
		},
		Scopes: []string{"openid", "offline"},
	}

	http.Handle("/", NewIndexPage())
	http.Handle("/callback", NewCallbackHandler(discoveryResponse.JWKSUri))

	err = http.ListenAndServe(":4000", http.DefaultServeMux)
	if err != nil {
		log.Panic(err)
	}
}

type callbackHandler struct {
	JwksUri string
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
	scope := request.URL.Query().Get("scope")
	state := request.URL.Query().Get("state")

	ctx := context.Background()

	httpClient, err := client2.TLSClient(client2.TLSClientOptions{InsecureSkipVerify: true})
	ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)

	tok, err := oauth2Config.Exchange(ctx, code)
	if err != nil {
		log.Print(err)
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	accessToken := tok.AccessToken
	refreshToken := tok.RefreshToken
	idToken := tok.Extra("id_token")

	keySet, err := jwk.FetchHTTP(c.JwksUri, jwk.WithHTTPClient(httpClient))
	if err != nil {
		log.Print(err)
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	parsedIdToken, err := jwt.Parse(strings.NewReader(idToken.(string)), jwt.WithKeySet(keySet))
	if err != nil {
		log.Print(err)
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	_, err = fmt.Fprintf(
		writer,
		"scope: %s, state: %s\ncode %s -> token %+v\n\naccess: %+v\nrefresh: %+v\nid: %+v\n\nParsed id token:\n%+v",
		code, scope, state, tok, accessToken, refreshToken, idToken, parsedIdToken)
	if err != nil {
		log.Print(err)
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
}

func NewCallbackHandler(jwksUri string) *callbackHandler {
	return &callbackHandler{JwksUri: jwksUri}
}

type indexHandler struct{}

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
	writer.Header().Add("Content-Type", "text/html")
	_, err := writer.Write([]byte(`
<!DOCTYPE html>
<html lang="en">
<head><title>Auth test</title></head>
<body>
<h1>Hello World</h1>
<a href="https://localhost:4444/oauth2/auth?client_id=local-test-app&response_type=code&scope=openid%20offline&state=12345678">Login</a>
</body>
</html>
`))
	if err != nil {
		log.Panic(err)
	}
}

func NewIndexPage() *indexHandler {
	return &indexHandler{}
}
