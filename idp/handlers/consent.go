package handlers

import (
	"context"
	"database/sql"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/go-playground/form/v4"
	"github.com/go-sql-driver/mysql"
	"github.com/gorilla/csrf"
	"github.com/lestrrat-go/jwx/jwt/openid"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	"github.com/ory/hydra-client-go/client/admin"
	"github.com/ory/hydra-client-go/models"
	log "github.com/sirupsen/logrus"

	commonServices "git.cacert.org/oidc_login/common/services"
	"git.cacert.org/oidc_login/idp/services"
)

type consentHandler struct {
	adminClient     *admin.Client
	bundle          *i18n.Bundle
	consentTemplate *template.Template
	context         context.Context
	logger          *log.Logger
	messageCatalog  *commonServices.MessageCatalog
}

type ConsentInformation struct {
	ConsentChecked bool `form:"consent"`
}

type UserInfo struct {
	Email         string         `db:"email"`
	EmailVerified bool           `db:"verified"`
	GivenName     string         `db:"fname"`
	MiddleName    string         `db:"mname"`
	FamilyName    string         `db:"lname"`
	BirthDate     mysql.NullTime `db:"dob"`
	Language      string         `db:"language"`
	Modified      mysql.NullTime `db:"modified"`
}

func (i *UserInfo) GetFullName() string {
	nameParts := make([]string, 0)
	if len(i.GivenName) > 0 {
		nameParts = append(nameParts, i.GivenName)
	}
	if len(i.MiddleName) > 0 {
		nameParts = append(nameParts, i.MiddleName)
	}
	if len(i.FamilyName) > 0 {
		nameParts = append(nameParts, i.FamilyName)
	}
	return strings.Join(nameParts, " ")
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
		h.renderConsentForm(w, r, consentData, err, localizer)
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

			db := services.GetDb(h.context)

			stmt, err := db.PreparexContext(
				r.Context(),
				`SELECT email, verified, fname, mname, lname, dob, language, modified
FROM users
WHERE id = ?
  AND LOCKED = 0`,
			)
			if err != nil {
				h.logger.Errorf("error preparing user information SQL: %v", err)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			defer func() { _ = stmt.Close() }()

			userInfo := &UserInfo{}

			err = stmt.QueryRowxContext(r.Context(), consentData.GetPayload().Subject).StructScan(userInfo)
			switch {
			case err == sql.ErrNoRows:
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				return
			case err != nil:
				h.logger.Errorf("error performing user information SQL: %v", err)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			default:
				for _, scope := range consentData.GetPayload().RequestedScope {
					switch scope {
					case "email":
						idTokenData[openid.EmailKey] = userInfo.Email
						idTokenData[openid.EmailVerifiedKey] = userInfo.EmailVerified
						break
					case "profile":
						idTokenData[openid.GivenNameKey] = userInfo.GivenName
						idTokenData[openid.FamilyNameKey] = userInfo.FamilyName
						idTokenData[openid.MiddleNameKey] = userInfo.MiddleName
						idTokenData[openid.NameKey] = userInfo.GetFullName()
						if userInfo.BirthDate.Valid {
							idTokenData[openid.BirthdateKey] = userInfo.BirthDate.Time.Format("2006-01-02")
						}
						idTokenData[openid.LocaleKey] = userInfo.Language
						idTokenData["https://cacert.localhost/groups"] = []string{"admin", "user"}
						if userInfo.Modified.Valid {
							idTokenData[openid.UpdatedAtKey] = userInfo.Modified.Time.Unix()
						}
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
				return
			}
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

func (h *consentHandler) renderConsentForm(w http.ResponseWriter, r *http.Request, consentData *admin.GetConsentRequestOK, err error, localizer *i18n.Localizer) {
	trans := func(id string, values ...map[string]interface{}) string {
		if len(values) > 0 {
			return h.messageCatalog.LookupMessage(id, values[0], localizer)
		}
		return h.messageCatalog.LookupMessage(id, nil, localizer)
	}

	// render consent form
	client := consentData.GetPayload().Client
	err = h.consentTemplate.Lookup("base").Execute(w, map[string]interface{}{
		"Title":          trans("TitleRequestConsent"),
		csrf.TemplateTag: csrf.TemplateField(r),
		"errors":         map[string]string{},
		"client":         client,
		"requestedScope": h.mapRequestedScope(consentData.GetPayload().RequestedScope, localizer),
		"LabelSubmit":    trans("LabelSubmit"),
		"LabelConsent":   trans("LabelConsent"),
		"IntroMoreInformation": template.HTML(trans("IntroConsentMoreInformation", map[string]interface{}{
			"client":     client.ClientName,
			"clientLink": client.ClientURI,
		})),
		"IntroConsentRequested": template.HTML(trans("IntroConsentRequested", map[string]interface{}{
			"client": client.ClientName,
		})),
	})
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

func NewConsentHandler(ctx context.Context, logger *log.Logger) (*consentHandler, error) {
	consentTemplate, err := template.ParseFiles(
		"templates/idp/base.gohtml", "templates/idp/consent.gohtml")
	if err != nil {
		return nil, err
	}

	return &consentHandler{
		adminClient:     ctx.Value(CtxAdminClient).(*admin.Client),
		bundle:          commonServices.GetI18nBundle(ctx),
		consentTemplate: consentTemplate,
		context:         ctx,
		logger:          logger,
		messageCatalog:  commonServices.GetMessageCatalog(ctx),
	}, nil
}
