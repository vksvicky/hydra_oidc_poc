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
	logger      *log.Logger
}

func (h *consentHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	consentChallenge := r.URL.Query().Get("consent_challenge")
	consentRequest, err := h.adminClient.AcceptConsentRequest(
		admin.NewAcceptConsentRequestParams().WithConsentChallenge(consentChallenge).WithBody(
			&models.AcceptConsentRequest{
				GrantAccessTokenAudience: nil,
				GrantScope:               []string{"openid", "offline"},
				HandledAt:                models.NullTime(time.Now()),
				Remember:                 true,
				RememberFor:              86400,
			}).WithTimeout(time.Second * 10))
	if err != nil {
		h.logger.Panic(err)
	}
	w.Header().Add("Location", *consentRequest.GetPayload().RedirectTo)
	w.WriteHeader(http.StatusFound)
}

func NewConsentHandler(logger *log.Logger, ctx context.Context) *consentHandler {
	return &consentHandler{
		logger:      logger,
		adminClient: ctx.Value(CtxAdminClient).(*admin.Client),
	}
}
