package handlers

import (
	"context"
	"fmt"
	"html/template"
	"net/http"
	"time"

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
	loginTemplate  *template.Template
	bundle         *i18n.Bundle
	messageCatalog map[string]*i18n.Message
	adminClient    *admin.Client
	logger         *log.Logger
}

type LoginInformation struct {
	Email    string `form:"email" validate:"required,email"`
	Password string `form:"password" validate:"required"`
}

func (h *loginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var err error
	challenge := r.URL.Query().Get("login_challenge")
	h.logger.Debugf("received challenge %s\n", challenge)
	validate := validator.New()

	switch r.Method {
	case http.MethodGet:
		// GET should render login form

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
		// POST should perform the action
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
				errors[err.Field()] = h.lookupErrorMessage(err.Tag(), err.Field(), err.Value(), i18n.NewLocalizer(h.bundle, accept))
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
				Acr:         "no-creds",
				Remember:    true,
				RememberFor: 0,
				Subject:     &subject,
			}).WithTimeout(time.Second * 10))
		if err != nil {
			h.logger.Errorf("error getting logout requests: %v", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}
		w.Header().Add("Location", *loginRequest.GetPayload().RedirectTo)
		w.WriteHeader(http.StatusFound)
		break
	default:
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
}

func (h *loginHandler) lookupErrorMessage(tag string, field string, value interface{}, l *i18n.Localizer) string {
	var message *i18n.Message
	message, ok := h.messageCatalog[fmt.Sprintf("%s-%s", field, tag)]
	if !ok {
		h.logger.Infof("no specific error message %s-%s", field, tag)
		message, ok = h.messageCatalog[tag]
		if !ok {
			h.logger.Infof("no specific error message %s", tag)
			message, ok = h.messageCatalog["unknown"]
			if !ok {
				h.logger.Error("no default translation found")
				return tag
			}
		}
	}

	translation, err := l.Localize(&i18n.LocalizeConfig{
		DefaultMessage: message,
		TemplateData: map[string]interface{}{
			"Value": value,
		},
	})
	if err != nil {
		h.logger.Error(err)
		return tag
	}
	return translation
}

func NewLoginHandler(logger *log.Logger, ctx context.Context) (*loginHandler, error) {
	loginTemplate, err := template.ParseFiles("templates/base.html", "templates/login.html")
	if err != nil {
		return nil, err
	}
	return &loginHandler{
		logger:         logger,
		loginTemplate:  loginTemplate,
		bundle:         ctx.Value(services.CtxI18nBundle).(*i18n.Bundle),
		messageCatalog: ctx.Value(services.CtxI18nCatalog).(map[string]*i18n.Message),
		adminClient:    ctx.Value(CtxAdminClient).(*admin.Client),
	}, nil
}
