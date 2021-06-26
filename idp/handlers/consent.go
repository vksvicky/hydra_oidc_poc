/*
 Copyright 2020, 2021 Jan Dittberner


 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
*/

package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"html/template"
	"net/http"
	"net/url"
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

	"git.cacert.org/oidc_login/common/handlers"
	commonModels "git.cacert.org/oidc_login/common/models"
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
	GrantedScopes  []string `form:"scope"`
	SelectedClaims []string `form:"claims"`
	ConsentChecked bool     `form:"consent"`
}

//goland:noinspection GoDeprecation needs mysql.NullTime needs to be used because sql.NullTime cannot handle byte arrays
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

var supportedScopes, supportedClaims map[string]*i18n.Message

const (
	ScopeOpenID        = "openid"
	ScopeOffline       = "offline"
	ScopeOfflineAccess = "offline_access"
	ScopeProfile       = "profile"
	ScopeEmail         = "email"

	ClaimCAcertGroups = "https://cacert.localhost/groups"
)

func init() {
	supportedScopes = make(map[string]*i18n.Message)
	supportedScopes[ScopeOpenID] = &i18n.Message{
		ID:    "Scope-openid-Description",
		Other: "Request information about your identity.",
	}
	supportedScopes[ScopeOffline] = &i18n.Message{
		ID:    "Scope-offline-Description",
		Other: "Keep access to your information until you revoke the permission.",
	}
	supportedScopes[ScopeOfflineAccess] = supportedScopes[ScopeOffline]
	supportedScopes[ScopeProfile] = &i18n.Message{
		ID:    "Scope-profile-Description",
		Other: "Access your user profile information including your name, birth date and locale.",
	}
	supportedScopes[ScopeEmail] = &i18n.Message{
		ID:    "Scope-email-Description",
		Other: "Access your primary email address.",
	}

	supportedClaims = make(map[string]*i18n.Message)
	supportedClaims[openid.SubjectKey] = nil
	supportedClaims[openid.EmailKey] = nil
	supportedClaims[openid.EmailVerifiedKey] = nil
	supportedClaims[openid.GivenNameKey] = nil
	supportedClaims[openid.FamilyNameKey] = nil
	supportedClaims[openid.MiddleNameKey] = nil
	supportedClaims[openid.NameKey] = nil
	supportedClaims[openid.BirthdateKey] = nil
	supportedClaims[openid.ZoneinfoKey] = nil
	supportedClaims[openid.LocaleKey] = nil
	supportedClaims[ClaimCAcertGroups] = &i18n.Message{
		ID:    "claim-CAcert-groups-description",
		Other: "Your CAcert team or group assignments.",
	}
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
	consentData, requestedClaims, err := h.getRequestedConsentInformation(challenge, r)
	if err != nil {
		// error is already handled in getRequestConsentInformation
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.renderConsentForm(w, r, consentData, requestedClaims, err, localizer)
		break
	case http.MethodPost:
		var consentInfo ConsentInformation

		// validate input
		decoder := form.NewDecoder()
		if err := decoder.Decode(&consentInfo, r.Form); err != nil {
			h.logger.Error(err)
			http.Error(
				w,
				http.StatusText(http.StatusInternalServerError),
				http.StatusInternalServerError,
			)
			return
		}

		if consentInfo.ConsentChecked {
			sessionData, err := h.getSessionData(consentInfo, requestedClaims, consentData.Payload, r.Context())
			if err != nil {
				h.logger.Errorf("could not get session data: %v", err)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}

			consentRequest, err := h.adminClient.AcceptConsentRequest(
				admin.NewAcceptConsentRequestParams().WithConsentChallenge(challenge).WithBody(
					&models.AcceptConsentRequest{
						GrantAccessTokenAudience: nil,
						GrantScope:               consentInfo.GrantedScopes,
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

func (h *consentHandler) getRequestedConsentInformation(challenge string, r *http.Request) (
	*admin.GetConsentRequestOK,
	*commonModels.OIDCClaimsRequest,
	error,
) {
	consentData, err := h.adminClient.GetConsentRequest(
		admin.NewGetConsentRequestParams().WithConsentChallenge(challenge))
	if err != nil {
		h.logger.Errorf("error getting consent information: %v", err)
		var errorDetails *handlers.ErrorDetails
		errorDetails = &handlers.ErrorDetails{
			ErrorMessage: "could not get consent details",
			ErrorDetails: []string{http.StatusText(http.StatusInternalServerError)},
		}
		handlers.GetErrorBucket(r).AddError(errorDetails)
		return nil, nil, err
	}
	var requestedClaims commonModels.OIDCClaimsRequest
	requestUrl, err := url.Parse(consentData.Payload.RequestURL)
	if err != nil {
		h.logger.Warnf("could not parse original request URL %s: %v", consentData.Payload.RequestURL, err)
	} else {
		claimsParameter := requestUrl.Query().Get("claims")
		if claimsParameter != "" {
			decoder := json.NewDecoder(strings.NewReader(claimsParameter))
			err := decoder.Decode(&requestedClaims)
			if err != nil {
				h.logger.Warnf(
					"ignoring claims request parameter %s that could not be decoded: %v",
					claimsParameter,
					err,
				)
			}
		}
	}
	return consentData, &requestedClaims, nil
}

func (h *consentHandler) renderConsentForm(
	w http.ResponseWriter,
	r *http.Request,
	consentData *admin.GetConsentRequestOK,
	claims *commonModels.OIDCClaimsRequest,
	err error,
	localizer *i18n.Localizer,
) {
	trans := func(id string, values ...map[string]interface{}) string {
		if len(values) > 0 {
			return h.messageCatalog.LookupMessage(id, values[0], localizer)
		}
		return h.messageCatalog.LookupMessage(id, nil, localizer)
	}

	// render consent form
	client := consentData.GetPayload().Client
	err = h.consentTemplate.Lookup("base").Execute(w, map[string]interface{}{
		"Title":           trans("TitleRequestConsent"),
		csrf.TemplateTag:  csrf.TemplateField(r),
		"errors":          map[string]string{},
		"client":          client,
		"requestedScope":  h.mapRequestedScope(consentData.GetPayload().RequestedScope, localizer),
		"requestedClaims": h.mapRequestedClaims(claims, localizer),
		"LabelSubmit":     trans("LabelSubmit"),
		"LabelConsent":    trans("LabelConsent"),
		"IntroMoreInformation": template.HTML(trans("IntroConsentMoreInformation", map[string]interface{}{
			"client":     client.ClientName,
			"clientLink": client.ClientURI,
		})),
		"ClaimsInformation": template.HTML(trans("ClaimsInformation", nil)),
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
		if _, ok := supportedScopes[scopeName]; !ok {
			h.logger.Warnf("unsupported scope %s ignored", scopeName)
			continue
		}
		label, err := localizer.Localize(&i18n.LocalizeConfig{
			DefaultMessage: supportedScopes[scopeName],
		})
		if err != nil {
			h.logger.Warnf("could not localize label for scope %s: %v", scopeName, err)
			label = scopeName
		}
		result = append(result, &scopeWithLabel{Name: scopeName, Label: label})
	}
	return result
}

type claimWithLabel struct {
	Name      string
	Label     string
	Essential bool
}

func (h *consentHandler) mapRequestedClaims(claims *commonModels.OIDCClaimsRequest, localizer *i18n.Localizer) []*claimWithLabel {
	result := make([]*claimWithLabel, 0)
	known := make(map[string]bool)

	for _, claimElement := range []*commonModels.ClaimElement{claims.GetUserInfo(), claims.GetIDToken()} {
		if claimElement != nil {
			for k, v := range *claimElement {
				if _, ok := supportedClaims[k]; !ok {
					h.logger.Warnf("unsupported claim %s ignored", k)
					continue
				}
				label, err := localizer.Localize(&i18n.LocalizeConfig{
					DefaultMessage: supportedClaims[k],
				})
				if err != nil {
					h.logger.Warnf("could not localize label for claim %s: %v", k, err)
					label = k
				}
				if !known[k] {
					result = append(result, &claimWithLabel{
						Name:      k,
						Label:     label,
						Essential: v.IsEssential(),
					})
					known[k] = true
				}
			}
		}
	}
	return result
}

func (h *consentHandler) getSessionData(
	info ConsentInformation,
	claims *commonModels.OIDCClaimsRequest,
	payload *models.ConsentRequest,
	ctx context.Context,
) (*models.ConsentRequestSession, error) {
	idTokenData := make(map[string]interface{}, 0)
	accessTokenData := make(map[string]interface{}, 0)

	db := services.GetDb(h.context)
	stmt, err := db.PreparexContext(
		ctx,
		`SELECT email, verified, fname, mname, lname, dob, language, modified
FROM users
WHERE uniqueid = ?
  AND locked = 0`,
	)
	if err != nil {
		h.logger.Errorf("error preparing user information SQL: %v", err)
		return nil, err
	}
	defer func() { _ = stmt.Close() }()

	userInfo := &UserInfo{}

	err = stmt.QueryRowxContext(ctx, payload.Subject).StructScan(userInfo)
	switch {
	case err == sql.ErrNoRows:
		h.logger.Errorf("could not find entry for subject %s", payload.Subject)
		return nil, err
	case err != nil:
		h.logger.Errorf("error performing user information SQL: %v", err)
		return nil, err
	default:
		h.fillTokenData(accessTokenData, payload.RequestedScope, claims, info, userInfo)
		h.fillTokenData(idTokenData, payload.RequestedScope, claims, info, userInfo)
		return &models.ConsentRequestSession{
			AccessToken: accessTokenData,
			IDToken:     idTokenData,
		}, nil
	}
}

func (h *consentHandler) fillTokenData(
	m map[string]interface{},
	requestedScope models.StringSlicePipeDelimiter,
	claimsRequest *commonModels.OIDCClaimsRequest,
	consentInformation ConsentInformation,
	userInfo *UserInfo,
) {
	for _, scope := range requestedScope {
		granted := false
		for _, k := range consentInformation.GrantedScopes {
			if k == scope {
				granted = true
				break
			}
		}
		if !granted {
			continue
		}
		switch scope {
		case ScopeEmail:
			// email
			// OPTIONAL. This scope value requests access to the email and
			// email_verified Claims.
			m[openid.EmailKey] = userInfo.Email
			m[openid.EmailVerifiedKey] = userInfo.EmailVerified
			break
		case ScopeProfile:
			// profile
			// OPTIONAL. This scope value requests access to the
			// End-User's default profile Claims, which are: name,
			// family_name, given_name, middle_name, nickname,
			// preferred_username, profile, picture, website, gender,
			// birthdate, zoneinfo, locale, and updated_at.
			m[openid.GivenNameKey] = userInfo.GivenName
			m[openid.FamilyNameKey] = userInfo.FamilyName
			m[openid.MiddleNameKey] = userInfo.MiddleName
			m[openid.NameKey] = userInfo.GetFullName()
			if userInfo.BirthDate.Valid {
				m[openid.BirthdateKey] = userInfo.BirthDate.Time.Format("2006-01-02")
			}
			m[openid.LocaleKey] = userInfo.Language
			if userInfo.Modified.Valid {
				m[openid.UpdatedAtKey] = userInfo.Modified.Time.Unix()
			}
			break
		}
	}
	if userInfoClaims := claimsRequest.GetUserInfo(); userInfoClaims != nil {
		for claimName, claim := range *userInfoClaims {
			granted := false
			for _, k := range consentInformation.SelectedClaims {
				if k == claimName {
					granted = true
					break
				}
			}
			if !granted {
				continue
			}
			if claim.WantedValue() != nil {
				m[claimName] = *claim.WantedValue()
				continue
			}
			switch claimName {
			case ClaimCAcertGroups:
				m[claimName] = []string{"admin", "user"}
				break
			default:
				if claim.IsEssential() {
					h.logger.Warnf(
						"handling for essential claim name %s not implemented",
						claimName,
					)
				} else {
					h.logger.Warnf(
						"handling for claim name %s not implemented",
						claimName,
					)
				}
			}
		}
	}
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
