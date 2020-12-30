package main

import (
	"context"
	"flag"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sync/atomic"
	"time"

	"github.com/BurntSushi/toml"
	openApiClient "github.com/go-openapi/runtime/client"
	"github.com/go-playground/form/v4"
	"github.com/go-playground/validator/v10"
	"github.com/gorilla/csrf"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	"github.com/ory/hydra-client-go/client"
	"github.com/ory/hydra-client-go/client/admin"
	"github.com/ory/hydra-client-go/models"
	log "github.com/sirupsen/logrus"
	"golang.org/x/text/language"
)

type key int

const (
	requestIdKey key = iota
)

var (
	adminClient    *client.OryHydra
	listenAddr     string
	healthy        int32
	validate       *validator.Validate
	bundle         *i18n.Bundle
	messageCatalog map[string]*i18n.Message
)

func main() {
	flag.StringVar(&listenAddr, "listen-addr", ":3000", "server listen address")
	flag.Parse()

	logger := log.New()
	logger.Infoln("Server is starting")

	validate = validator.New()

	router := http.NewServeMux()
	loginHandler, err := NewLoginHandler()
	router.Handle("/login", loginHandler)
	router.Handle("/consent", NewConsentHandler())
	router.Handle("/health", health())

	adminURL, err := url.Parse("https://localhost:4445/")
	if err != nil {
		log.Panic(err)
	}
	apiClient, err := openApiClient.TLSClient(openApiClient.TLSClientOptions{InsecureSkipVerify: true})
	if err != nil {
		log.Panic(err)
	}
	clientTransport := openApiClient.NewWithClient(adminURL.Host, adminURL.Path, []string{adminURL.Scheme}, apiClient)
	adminClient = client.New(clientTransport, nil)

	if err != nil {
		log.Fatal(err)
	}

	csrfKey := []byte("abcdefghijklmnopqrstuvwxyz012345")
	handler := csrf.Protect(csrfKey)(router)

	nextRequestId := func() string {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}

	bundle = i18n.NewBundle(language.English)
	bundle.RegisterUnmarshalFunc("toml", toml.Unmarshal)
	_, err = bundle.LoadMessageFile("de.toml")
	if err != nil {
		logger.Warnln("message bundle de.toml not found")
	}

	initMessageCatalog()

	server := &http.Server{
		Addr:         ":3000",
		Handler:      tracing(nextRequestId)(logging(logger)(handler)),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  15 * time.Second,
	}

	done := make(chan bool)
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)

	go func() {
		<-quit
		logger.Infoln("Server is shutting down...")
		atomic.StoreInt32(&healthy, 0)

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		server.SetKeepAlivesEnabled(false)
		if err := server.Shutdown(ctx); err != nil {
			logger.Fatalf("Could not gracefully shutdown the server: %v\n", err)
		}
		close(done)
	}()

	logger.Infoln("Server is ready to handle requests at", listenAddr)
	atomic.StoreInt32(&healthy, 1)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Fatalf("Could not listen on %s: %v\n", listenAddr, err)
	}

	<-done
	logger.Infoln("Server stopped")
}

func initMessageCatalog() {
	messageCatalog = make(map[string]*i18n.Message)
	messageCatalog["unknown"] = &i18n.Message{
		ID:    "ErrorUnknown",
		Other: "Unknown error",
	}
	messageCatalog["email"] = &i18n.Message{
		ID:    "ErrorEmail",
		Other: "Please enter a valid email address.",
	}
	messageCatalog["Email-required"] = &i18n.Message{
		ID:    "ErrorEmailRequired",
		Other: "Please enter an email address.",
	}
	messageCatalog["required"] = &i18n.Message{
		ID:    "ErrorRequired",
		Other: "Please enter a value",
	}
	messageCatalog["Password-required"] = &i18n.Message{
		ID:    "ErrorPasswordRequired",
		Other: "Please enter a password.",
	}
}

func health() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.LoadInt32(&healthy) == 1 {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	})
}

func logging(logger *log.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				requestId, ok := r.Context().Value(requestIdKey).(string)
				if !ok {
					requestId = "unknown"
				}
				logger.Infoln(requestId, r.Method, r.URL.Path, r.RemoteAddr, r.UserAgent())
			}()
			next.ServeHTTP(w, r)
		})
	}
}

func tracing(nextRequestId func() string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestId := r.Header.Get("X-Request-Id")
			if requestId == "" {
				requestId = nextRequestId()
			}
			ctx := context.WithValue(r.Context(), requestIdKey, requestId)
			w.Header().Set("X-Request-Id", requestId)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
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
	loginTemplate *template.Template
}

type LoginInformation struct {
	Email    string `form:"email" validate:"required,email"`
	Password string `form:"password" validate:"required"`
}

func (l *loginHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	var err error
	challenge := request.URL.Query().Get("login_challenge")
	log.Debugf("received challenge %s\n", challenge)

	switch request.Method {
	case http.MethodGet:
		// GET should render login form

		err = l.loginTemplate.Lookup("base").Execute(writer, map[string]interface{}{
			"Title":          "Title",
			csrf.TemplateTag: csrf.TemplateField(request),
			"LabelEmail":     "Email",
			"LabelPassword":  "Password",
			"LabelLogin":     "Login",
			"errors":         map[string]string{},
		})
		if err != nil {
			log.Error(err)
			http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		break
	case http.MethodPost:
		// POST should perform the action
		var loginInfo LoginInformation

		// validate input
		decoder := form.NewDecoder()
		err = decoder.Decode(&loginInfo, request.Form)
		if err != nil {
			log.Error(err)
			http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		err := validate.Struct(&loginInfo)
		if err != nil {
			errors := make(map[string]string)
			for _, err := range err.(validator.ValidationErrors) {
				accept := request.Header.Get("Accept-Language")
				errors[err.Field()] = lookupErrorMessage(err.Tag(), err.Field(), err.Value(), i18n.NewLocalizer(bundle, accept))
			}

			err = l.loginTemplate.Lookup("base").Execute(writer, map[string]interface{}{
				"Title":          "Title",
				csrf.TemplateTag: csrf.TemplateField(request),
				"LabelEmail":     "Email",
				"LabelPassword":  "Password",
				"LabelLogin":     "Login",
				"Email":          loginInfo.Email,
				"errors":         errors,
			})
			if err != nil {
				log.Error(err)
				http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			return
		}

		// GET user data
		// finish login and redirect to target
		// TODO: get or generate a user id
		subject := "a-user-with-an-id"
		loginRequest, err := adminClient.Admin.AcceptLoginRequest(
			admin.NewAcceptLoginRequestParams().WithLoginChallenge(challenge).WithBody(&models.AcceptLoginRequest{
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
		break
	default:
		http.Error(writer, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
}

func lookupErrorMessage(tag string, field string, value interface{}, l *i18n.Localizer) string {
	var message *i18n.Message
	message, ok := messageCatalog[fmt.Sprintf("%s-%s", field, tag)]
	if !ok {
		log.Infof("no specific error message %s-%s", field, tag)
		message, ok = messageCatalog[tag]
		if !ok {
			log.Infof("no specific error message %s", tag)
			message, ok = messageCatalog["unknown"]
			if !ok {
				log.Error("no default translation found")
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
		log.Error(err)
		return tag
	}
	return translation
}

func NewLoginHandler() (*loginHandler, error) {
	loginTemplate, err := template.ParseFiles("templates/base.html", "templates/login.html")
	if err != nil {
		return nil, err
	}
	return &loginHandler{loginTemplate: loginTemplate}, nil
}
