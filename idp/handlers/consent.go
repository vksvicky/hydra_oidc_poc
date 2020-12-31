package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/ory/hydra-client-go/client/admin"
	"github.com/ory/hydra-client-go/models"
	log "github.com/sirupsen/logrus"
)

type consentHandler struct {
	adminClient *admin.Client
}

func (c *consentHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	consentChallenge := request.URL.Query().Get("consent_challenge")
	consentRequest, err := c.adminClient.AcceptConsentRequest(
		admin.NewAcceptConsentRequestParams().WithConsentChallenge(consentChallenge).WithBody(
			&models.AcceptConsentRequest{
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

func NewConsentHandler(ctx context.Context) *consentHandler {
	return &consentHandler{
		adminClient: ctx.Value(CtxAdminClient).(*admin.Client),
	}
}
