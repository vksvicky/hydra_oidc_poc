package handlers

import (
	"context"
	"fmt"
	"html/template"
	"net/http"
	"time"

	"github.com/go-playground/form/v4"
	"github.com/gorilla/csrf"
	"github.com/lestrrat-go/jwx/jwt/openid"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	"github.com/ory/hydra-client-go/client/admin"
	"github.com/ory/hydra-client-go/models"
	log "github.com/sirupsen/logrus"

	"git.cacert.org/oidc_login/idp/services"
)

type consentHandler struct {
	adminClient     *admin.Client
	bundle          *i18n.Bundle
	consentTemplate *template.Template
	logger          *log.Logger
	messageCatalog  *services.MessageCatalog
}

type ConsentInformation struct {
	ConsentChecked bool `form:"consent"`
}

func (h *consentHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	challenge := r.URL.Query().Get("consent_challenge")
	h.logger.Debugf("received consent challenge %s", challenge)
	accept := r.Header.Get("Accept-Language")
	localizer := i18n.NewLocalizer(h.bundle, accept)

	// retrieve consent information
	consentData, err := h.adminClient.GetConsentRequest(
		admin.NewGetConsentRequestParams().WithConsentChallenge(challenge))
	if err != nil {
		h.logger.Error("error getting consent information: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	switch r.Method {
	case http.MethodGet:
		trans := h.messageCatalog.LookupMessage

		// render consent form
		client := consentData.GetPayload().Client
		err = h.consentTemplate.Lookup("base").Execute(w, map[string]interface{}{
			"Title":          trans("TitleRequestConsent", nil, localizer),
			csrf.TemplateTag: csrf.TemplateField(r),
			"errors":         map[string]string{},
			"client":         client,
			"requestedScope": h.mapRequestedScope(consentData.GetPayload().RequestedScope, localizer),
			"LabelSubmit":    trans("LabelSubmit", nil, localizer),
			"LabelConsent":   trans("LabelConsent", nil, localizer),
			"IntroMoreInformation": template.HTML(trans("IntroConsentMoreInformation", map[string]interface{}{
				"client":     client.ClientName,
				"clientLink": client.ClientURI,
			}, localizer)),
			"IntroConsentRequested": template.HTML(trans("IntroConsentRequested", map[string]interface{}{
				"client": client.ClientName,
			}, localizer)),
		})
		break
	case http.MethodPost:
		var consentInfo ConsentInformation

		// validate input
		decoder := form.NewDecoder()
		if err := decoder.Decode(&consentInfo, r.Form); err != nil {
			h.logger.Error(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		if consentInfo.ConsentChecked {
			idTokenData := make(map[string]interface{}, 0)

			for _, scope := range consentData.GetPayload().RequestedScope {
				switch scope {
				case "email":
					idTokenData[openid.EmailKey] = "john@theripper.mil"
					idTokenData[openid.EmailVerifiedKey] = true
					break
				case "profile":
					idTokenData[openid.GivenNameKey] = "John"
					idTokenData[openid.FamilyNameKey] = "The ripper"
					idTokenData[openid.MiddleNameKey] = ""
					idTokenData[openid.NameKey] = "John the Ripper"
					idTokenData[openid.BirthdateKey] = "1970-01-01"
					idTokenData[openid.ZoneinfoKey] = "Europe/London"
					idTokenData[openid.LocaleKey] = "en_UK"
					idTokenData["https://cacert.localhost/groups"] = []string{"admin", "user"}
					break
				}
			}

			sessionData := &models.ConsentRequestSession{
				AccessToken: nil,
				IDToken:     idTokenData,
			}
			consentRequest, err := h.adminClient.AcceptConsentRequest(
				admin.NewAcceptConsentRequestParams().WithConsentChallenge(challenge).WithBody(
					&models.AcceptConsentRequest{
						GrantAccessTokenAudience: nil,
						GrantScope:               consentData.GetPayload().RequestedScope,
						HandledAt:                models.NullTime(time.Now()),
						Remember:                 true,
						RememberFor:              86400,
						Session:                  sessionData,
					}).WithTimeout(time.Second * 10))
			if err != nil {
				h.logger.Error(err)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			w.Header().Add("Location", *consentRequest.GetPayload().RedirectTo)
			w.WriteHeader(http.StatusFound)
		} else {
			consentRequest, err := h.adminClient.RejectConsentRequest(
				admin.NewRejectConsentRequestParams().WithConsentChallenge(challenge).WithBody(
					&models.RejectRequest{}))
			if err != nil {
				h.logger.Error(err)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			w.Header().Add("Location", *consentRequest.GetPayload().RedirectTo)
			w.WriteHeader(http.StatusFound)
		}
	}
}

type scopeWithLabel struct {
	Name  string
	Label string
}

func (h *consentHandler) mapRequestedScope(scope models.StringSlicePipeDelimiter, localizer *i18n.Localizer) []*scopeWithLabel {
	result := make([]*scopeWithLabel, 0)
	for _, scopeName := range scope {
		result = append(result, &scopeWithLabel{Name: scopeName, Label: h.messageCatalog.LookupMessage(
			fmt.Sprintf("Scope-%s-Description", scopeName), nil, localizer)})
	}
	return result
}

func NewConsentHandler(logger *log.Logger, ctx context.Context) (*consentHandler, error) {
	consentTemplate, err := template.ParseFiles("templates/base.gohtml", "templates/consent.gohtml")
	if err != nil {
		return nil, err
	}

	return &consentHandler{
		adminClient:     ctx.Value(CtxAdminClient).(*admin.Client),
		bundle:          ctx.Value(services.CtxI18nBundle).(*i18n.Bundle),
		consentTemplate: consentTemplate,
		logger:          logger,
		messageCatalog:  ctx.Value(services.CtxI18nCatalog).(*services.MessageCatalog),
	}, nil
}
