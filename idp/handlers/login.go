package handlers

import (
	"context"
	"crypto/sha1"
	"database/sql"
	"encoding/hex"
	"html/template"
	"net/http"
	"time"

	"github.com/go-openapi/runtime"
	"github.com/go-playground/form/v4"
	"github.com/go-playground/validator/v10"
	"github.com/gorilla/csrf"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	"github.com/ory/hydra-client-go/client/admin"
	"github.com/ory/hydra-client-go/models"
	log "github.com/sirupsen/logrus"

	commonServices "git.cacert.org/oidc_login/common/services"
	"git.cacert.org/oidc_login/idp/services"
)

type loginHandler struct {
	adminClient    *admin.Client
	bundle         *i18n.Bundle
	context        context.Context
	logger         *log.Logger
	loginTemplate  *template.Template
	messageCatalog *commonServices.MessageCatalog
}

type acrType string

const (
	NoCredentials          acrType = "none"
	ClientCertificate      acrType = "cert"
	ClientCertificateOTP   acrType = "cert+otp"
	ClientCertificateToken acrType = "cert+token"
	Password               acrType = "password"
	PasswordOTP            acrType = "password+otp"
	PasswordToken          acrType = "password+token"
)

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

	validate := validator.New()

	switch r.Method {
	case http.MethodGet:
		// render login form
		h.renderLoginForm(w, r, map[string]string{}, &LoginInformation{}, localizer)
		break
	case http.MethodPost:
		var loginInfo LoginInformation

		// validate input
		decoder := form.NewDecoder()
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
				errors[err.Field()] = h.messageCatalog.LookupErrorMessage(err.Tag(), err.Field(), err.Value(), i18n.NewLocalizer(h.bundle, accept))
			}
			h.renderLoginForm(w, r, errors, &loginInfo, localizer)
			return
		}

		db := services.GetDb(h.context)

		stmt, err := db.PrepareContext(
			r.Context(),
			`SELECT id
FROM users
WHERE email = ?
  AND password = ?
  AND locked = 0`,
		)
		if err != nil {
			h.logger.Errorf("error preparing login SQL: %v", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		defer func() { _ = stmt.Close() }()

		// FIXME: replace with a real password hash algorithm
		passwordHash := sha1.Sum([]byte(loginInfo.Password))
		password := hex.EncodeToString(passwordHash[:])
		// FIXME: introduce a real opaque identifier (i.e. a UUID)
		var userId string
		// GET user data
		err = stmt.QueryRowContext(r.Context(), loginInfo.Email, password).Scan(&userId)
		switch {
		case err == sql.ErrNoRows:
			errors := map[string]string{
				"Form": h.messageCatalog.LookupMessage(
					"WrongOrLockedUserOrInvalidPassword",
					nil,
					localizer,
				),
			}
			h.renderLoginForm(w, r, errors, &loginInfo, localizer)
			return
		case err != nil:
			h.logger.Errorf("error performing login SQL: %v", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		default:
			// finish login and redirect to target
			loginRequest, err := h.adminClient.AcceptLoginRequest(
				admin.NewAcceptLoginRequestParams().WithLoginChallenge(challenge).WithBody(&models.AcceptLoginRequest{
					Acr:         string(Password),
					Remember:    true,
					RememberFor: 0,
					Subject:     &userId,
				}).WithTimeout(time.Second * 10))
			if err != nil {
				h.logger.Errorf("error getting login request: %#v", err)
				http.Error(w, err.Error(), err.(*runtime.APIError).Code)
				return
			}
			w.Header().Add("Location", *loginRequest.GetPayload().RedirectTo)
			w.WriteHeader(http.StatusFound)
		}
		break
	default:
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
}

func (h *loginHandler) renderLoginForm(w http.ResponseWriter, r *http.Request, errors map[string]string, info *LoginInformation, localizer *i18n.Localizer) {
	trans := func(label string) string {
		return h.messageCatalog.LookupMessage(label, nil, localizer)
	}

	err := h.loginTemplate.Lookup("base").Execute(w, map[string]interface{}{
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

func NewLoginHandler(ctx context.Context, logger *log.Logger) (*loginHandler, error) {
	loginTemplate, err := template.ParseFiles(
		"templates/idp/base.gohtml", "templates/idp/login.gohtml")
	if err != nil {
		return nil, err
	}
	return &loginHandler{
		adminClient:    ctx.Value(CtxAdminClient).(*admin.Client),
		bundle:         commonServices.GetI18nBundle(ctx),
		context:        ctx,
		logger:         logger,
		loginTemplate:  loginTemplate,
		messageCatalog: commonServices.GetMessageCatalog(ctx),
	}, nil
}
