package handlers

import (
	"context"
	"crypto/sha1"
	"database/sql"
	"encoding/hex"
	"html/template"
	"net/http"
	"strconv"
	"time"

	"github.com/go-playground/form/v4"
	"github.com/go-playground/validator/v10"
	"github.com/gorilla/csrf"
	"github.com/jmoiron/sqlx"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	"github.com/ory/hydra-client-go/client/admin"
	"github.com/ory/hydra-client-go/models"
	log "github.com/sirupsen/logrus"

	"git.cacert.org/oidc_login/common/handlers"
	commonServices "git.cacert.org/oidc_login/common/services"
	"git.cacert.org/oidc_login/idp/services"
)

type acrType string

const (
	ClientCertificate acrType = "cert"     // client certificate login
	Password          acrType = "password" // regular username + password login
	// ClientCertificateOTP   acrType = "cert+otp"
	// ClientCertificateToken acrType = "cert+token"
	// PasswordOTP            acrType = "password+otp"
	// PasswordToken          acrType = "password+token"
)

type loginHandler struct {
	adminClient    *admin.Client
	bundle         *i18n.Bundle
	context        context.Context
	logger         *log.Logger
	templates      map[acrType]*template.Template
	messageCatalog *commonServices.MessageCatalog
}

type LoginInformation struct {
	Email    string `form:"email" validate:"required,email"`
	Password string `form:"password" validate:"required"`
}

func (h *loginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var err error
	challenge := r.URL.Query().Get("login_challenge")
	h.logger.Debugf("received login challenge %s\n", challenge)
	accept := r.Header.Get("Accept-Language")
	localizer := i18n.NewLocalizer(h.bundle, accept)

	certEmails := h.getCertEmails(r)

	var loginInfo LoginInformation
	validate := validator.New()

	switch r.Method {
	case http.MethodGet:
		if certEmails != nil {
			h.renderRequestForClientCert(w, r, certEmails, localizer)
		} else {
			// render login form
			h.renderLoginForm(w, r, map[string]string{}, &LoginInformation{}, localizer)
		}
		break
	case http.MethodPost:
		var userId *string
		var authMethod acrType

		if certEmails != nil && r.PostFormValue("action") == "cert-login" {
			if r.PostFormValue("use-certificate") == "" {
				// render login form
				h.renderLoginForm(w, r, map[string]string{}, &LoginInformation{}, localizer)
				return
			}
			// perform certificate auth
			h.logger.Infof("would perform certificate authentication with: %+v", certEmails)
			userId, err = h.performCertificateLogin(certEmails, r)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			if userId == nil {
				errors := map[string]string{
					"Form": h.messageCatalog.LookupMessage(
						"WrongOrLockedUserOrInvalidPassword",
						nil,
						localizer,
					),
				}
				h.renderLoginForm(w, r, errors, &loginInfo, localizer)
				return
			}
			authMethod = ClientCertificate
		} else {
			decoder := form.NewDecoder()
			// validate input
			err = decoder.Decode(&loginInfo, r.Form)
			if err != nil {
				h.logger.Error(err)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			err := validate.Struct(&loginInfo)
			if err != nil {
				errors := make(map[string]string)
				for _, err := range err.(validator.ValidationErrors) {
					accept := r.Header.Get("Accept-Language")
					errors[err.Field()] = h.messageCatalog.LookupErrorMessage(
						err.Tag(),
						err.Field(),
						err.Value(),
						i18n.NewLocalizer(h.bundle, accept),
					)
				}
				h.renderLoginForm(w, r, errors, &loginInfo, localizer)
				return
			}
			userId, err = h.performUserNamePasswordLogin(&loginInfo, r)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			if userId == nil {
				errors := map[string]string{
					"Form": h.messageCatalog.LookupMessage(
						"WrongOrLockedUserOrInvalidPassword",
						nil,
						localizer,
					),
				}
				h.renderLoginForm(w, r, errors, &loginInfo, localizer)
				return
			}
			authMethod = Password
		}

		// finish login and redirect to target
		loginRequest, err := h.adminClient.AcceptLoginRequest(
			admin.NewAcceptLoginRequestParams().WithLoginChallenge(challenge).WithBody(
				&models.AcceptLoginRequest{
					Acr:         string(authMethod),
					Remember:    true,
					RememberFor: 0,
					Subject:     userId,
				}).WithTimeout(time.Second * 10))
		if err != nil {
			h.logger.Errorf("error getting login request: %#v", err)
			var errorDetails *handlers.ErrorDetails
			switch v := err.(type) {
			case *admin.AcceptLoginRequestNotFound:
				errorDetails = &handlers.ErrorDetails{
					ErrorMessage: *v.Payload.Error,
					ErrorDetails: []string{v.Payload.ErrorDescription},
				}
				if v.Payload.StatusCode != 0 {
					errorDetails.ErrorCode = strconv.Itoa(int(v.Payload.StatusCode))
				}
				break
			default:
				errorDetails = &handlers.ErrorDetails{
					ErrorMessage: "could not accept login",
					ErrorDetails: []string{err.Error()},
				}
			}
			handlers.GetErrorBucket(r).AddError(errorDetails)
			return
		}
		w.Header().Add("Location", *loginRequest.GetPayload().RedirectTo)
		w.WriteHeader(http.StatusFound)
	default:
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
}

func (h *loginHandler) getCertEmails(r *http.Request) []string {
	if r.TLS != nil && r.TLS.PeerCertificates != nil && len(r.TLS.PeerCertificates) > 0 {
		firstCert := r.TLS.PeerCertificates[0]
		for _, email := range firstCert.EmailAddresses {
			h.logger.Infof("authenticated with a client certificate for email address %s", email)
		}
		return firstCert.EmailAddresses
	}
	return nil
}

func (h *loginHandler) renderLoginForm(w http.ResponseWriter, r *http.Request, errors map[string]string, info *LoginInformation, localizer *i18n.Localizer) {
	trans := func(label string) string {
		return h.messageCatalog.LookupMessage(label, nil, localizer)
	}

	err := h.templates[Password].Lookup("base").Execute(w, map[string]interface{}{
		"Title":          trans("LoginTitle"),
		csrf.TemplateTag: csrf.TemplateField(r),
		"LabelEmail":     trans("LabelEmail"),
		"LabelPassword":  trans("LabelPassword"),
		"LabelLogin":     trans("LabelLogin"),
		"Email":          info.Email,
		"errors":         errors,
	})
	if err != nil {
		h.logger.Error(err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
}

func (h *loginHandler) renderRequestForClientCert(w http.ResponseWriter, r *http.Request, emails []string, localizer *i18n.Localizer) {
	trans := func(label string) string {
		return h.messageCatalog.LookupMessage(label, nil, localizer)
	}

	err := h.templates[ClientCertificate].Lookup("base").Execute(w, map[string]interface{}{
		"Title":          trans("LoginTitle"),
		csrf.TemplateTag: csrf.TemplateField(r),
		"IntroText":      trans("CertLoginIntroText"),
		"emails":         emails,
		"RequestText":    trans("CertLoginRequestText"),
		"AcceptLabel":    trans("LabelAcceptCertLogin"),
		"RejectLabel":    trans("LabelRejectCertLogin"),
	})
	if err != nil {
		h.logger.Error(err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
}

func (h *loginHandler) performUserNamePasswordLogin(loginInfo *LoginInformation, r *http.Request) (*string, error) {
	db := services.GetDb(h.context)

	stmt, err := db.PrepareContext(
		r.Context(),
		`SELECT uniqueID
FROM users
WHERE email = ?
  AND password = ?
  AND locked = 0`,
	)
	if err != nil {
		h.logger.Errorf("error preparing login SQL: %v", err)
		return nil, err
	}
	defer func() { _ = stmt.Close() }()

	// FIXME: replace with a real password hash algorithm
	passwordHash := sha1.Sum([]byte(loginInfo.Password))
	password := hex.EncodeToString(passwordHash[:])

	var userId string
	// GET user data
	err = stmt.QueryRowContext(r.Context(), loginInfo.Email, password).Scan(&userId)
	switch {
	case err == sql.ErrNoRows:
		return nil, nil
	case err != nil:
		h.logger.Errorf("error performing login SQL: %v", err)
		return nil, err
	default:
		h.logger.Infof("found user %s", userId)
		return &userId, nil
	}
}

func (h *loginHandler) performCertificateLogin(emails []string, r *http.Request) (*string, error) {
	db := services.GetDb(h.context)

	query, args, err := sqlx.In(
		`SELECT DISTINCT u.uniqueid
FROM users u
         JOIN email e ON e.memid = u.id
WHERE e.email IN (?)
  AND u.locked = 0`,
		emails,
	)
	if err != nil {
		h.logger.Errorf("could not parse IN query for certificate login: %v", err)
		return nil, err
	}
	stmt, err := db.PreparexContext(r.Context(), query)
	if err != nil {
		h.logger.Errorf("error preparing login SQL: %v", err)
		return nil, err
	}
	defer func() { _ = stmt.Close() }()

	var userId string
	err = stmt.QueryRowContext(r.Context(), args...).Scan(&userId)
	switch {
	case err == sql.ErrNoRows:
		return nil, nil
	case err != nil:
		h.logger.Errorf("error performing login SQL: %v", err)
		return nil, err
	default:
		h.logger.Infof("found user %s", userId)
		return &userId, nil
	}
}

func NewLoginHandler(ctx context.Context, logger *log.Logger) (*loginHandler, error) {
	var err error
	loginTemplate, err := template.ParseFiles(
		"templates/idp/base.gohtml", "templates/idp/login.gohtml")
	if err != nil {
		return nil, err
	}
	clientCertTemplate, err := template.ParseFiles(
		"templates/idp/base.gohtml", "templates/idp/client_certificate.gohtml")
	if err != nil {
		return nil, err
	}
	formTemplates := map[acrType]*template.Template{
		Password:          loginTemplate,
		ClientCertificate: clientCertTemplate,
	}
	return &loginHandler{
		adminClient:    ctx.Value(CtxAdminClient).(*admin.Client),
		bundle:         commonServices.GetI18nBundle(ctx),
		context:        ctx,
		logger:         logger,
		templates:      formTemplates,
		messageCatalog: commonServices.GetMessageCatalog(ctx),
	}, nil
}
