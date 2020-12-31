package handlers

import (
	"context"
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

	"git.cacert.org/oidc_login/idp/services"
)

type loginHandler struct {
	adminClient    *admin.Client
	bundle         *i18n.Bundle
	logger         *log.Logger
	loginTemplate  *template.Template
	messageCatalog *services.MessageCatalog
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
	validate := validator.New()

	switch r.Method {
	case http.MethodGet:
		// render login form
		err = h.loginTemplate.Lookup("base").Execute(w, map[string]interface{}{
			"Title":          "Title",
			csrf.TemplateTag: csrf.TemplateField(r),
			"LabelEmail":     "Email",
			"LabelPassword":  "Password",
			"LabelLogin":     "Login",
			"errors":         map[string]string{},
		})
		if err != nil {
			h.logger.Error(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
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

			err = h.loginTemplate.Lookup("base").Execute(w, map[string]interface{}{
				"Title":          "Title",
				csrf.TemplateTag: csrf.TemplateField(r),
				"LabelEmail":     "Email",
				"LabelPassword":  "Password",
				"LabelLogin":     "Login",
				"Email":          loginInfo.Email,
				"errors":         errors,
			})
			if err != nil {
				h.logger.Error(err)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			return
		}

		// GET user data
		// finish login and redirect to target
		// TODO: get or generate a user id
		subject := "a-user-with-an-id"
		loginRequest, err := h.adminClient.AcceptLoginRequest(
			admin.NewAcceptLoginRequestParams().WithLoginChallenge(challenge).WithBody(&models.AcceptLoginRequest{
				Acr:         string(NoCredentials),
				Remember:    true,
				RememberFor: 0,
				Subject:     &subject,
			}).WithTimeout(time.Second * 10))
		if err != nil {
			h.logger.Errorf("error getting login request: %#v", err)
			http.Error(w, err.Error(), err.(*runtime.APIError).Code)
			return
		}
		w.Header().Add("Location", *loginRequest.GetPayload().RedirectTo)
		w.WriteHeader(http.StatusFound)
		break
	default:
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
}

func NewLoginHandler(logger *log.Logger, ctx context.Context) (*loginHandler, error) {
	loginTemplate, err := template.ParseFiles("templates/base.gohtml", "templates/login.gohtml")
	if err != nil {
		return nil, err
	}
	return &loginHandler{
		adminClient:    ctx.Value(CtxAdminClient).(*admin.Client),
		bundle:         ctx.Value(services.CtxI18nBundle).(*i18n.Bundle),
		logger:         logger,
		loginTemplate:  loginTemplate,
		messageCatalog: ctx.Value(services.CtxI18nCatalog).(*services.MessageCatalog),
	}, nil
}
