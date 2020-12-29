package main

import (
	"log"
	"net/http"
	"net/url"
	"time"

	openApiClient "github.com/go-openapi/runtime/client"
	"github.com/ory/hydra-client-go/client"
	"github.com/ory/hydra-client-go/client/admin"
	"github.com/ory/hydra-client-go/models"
)

var adminClient *client.OryHydra

func main() {
	adminURL, err := url.Parse("https://localhost:4445/")
	if err != nil {
		log.Panic(err)
	}
	apiclient, err := openApiClient.TLSClient(openApiClient.TLSClientOptions{InsecureSkipVerify: true})
	if err != nil {
		log.Panic(err)
	}
	clientTransport := openApiClient.NewWithClient(adminURL.Host, adminURL.Path, []string{adminURL.Scheme}, apiclient)
	adminClient = client.New(clientTransport, nil)

	http.Handle("/login", NewLoginHandler())
	http.Handle("/consent", NewConsentHandler())

	err = http.ListenAndServe(":3000", http.DefaultServeMux)
	if err != nil {
		log.Panic(err)
	}
}

type consentHandler struct {
}

func (c *consentHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	consentChallenge := request.URL.Query().Get("consent_challenge")
	consentRequest, err := adminClient.Admin.AcceptConsentRequest(admin.NewAcceptConsentRequestParams().WithConsentChallenge(consentChallenge).WithBody(&models.AcceptConsentRequest{
		GrantAccessTokenAudience: nil,
		GrantScope:               []string{"openid", "offline"},
		HandledAt:                models.NullTime(time.Now()),
		Remember:                 true,
		RememberFor:              86400,
	}).WithTimeout(time.Second * 10))
	if err != nil {
		log.Panic(err)
	}
	writer.Header().Add("Location", *consentRequest.GetPayload().RedirectTo)
	writer.WriteHeader(http.StatusFound)
}

func NewConsentHandler() *consentHandler {
	return &consentHandler{}
}

type loginHandler struct {
}

func (l *loginHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	challenge := request.URL.Query().Get("login_challenge")
	log.Printf("received challenge %s\n", challenge)

	// GET should render login form

	// POST should perform the action

	subject := "a-user-with-an-id"
	loginRequest, err := adminClient.Admin.AcceptLoginRequest(admin.NewAcceptLoginRequestParams().WithLoginChallenge(challenge).WithBody(&models.AcceptLoginRequest{
		Acr:         "no-creds",
		Remember:    true,
		RememberFor: 0,
		Subject:     &subject,
	}).WithTimeout(time.Second * 10))
	if err != nil {
		log.Panic(err)
	}
	writer.Header().Add("Location", *loginRequest.GetPayload().RedirectTo)
	writer.WriteHeader(http.StatusFound)
}

func NewLoginHandler() *loginHandler {
	return &loginHandler{}
}
