package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"time"

	"github.com/go-openapi/runtime/client"
	"github.com/gorilla/csrf"
	"github.com/knadh/koanf"
	"github.com/knadh/koanf/parsers/toml"
	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/providers/posflag"
	hydra "github.com/ory/hydra-client-go/client"
	log "github.com/sirupsen/logrus"
	flag "github.com/spf13/pflag"

	commonHandlers "git.cacert.org/oidc_login/common/handlers"
	commonServices "git.cacert.org/oidc_login/common/services"
	"git.cacert.org/oidc_login/idp/handlers"
	"git.cacert.org/oidc_login/idp/services"
)

func main() {
	f := flag.NewFlagSet("config", flag.ContinueOnError)
	f.Usage = func() {
		fmt.Println(f.FlagUsages())
		os.Exit(0)
	}
	f.StringSlice("conf", []string{"idp.toml"}, "path to one or more .toml files")
	logger := log.New()
	var err error

	if err = f.Parse(os.Args[1:]); err != nil {
		logger.Fatal(err)
	}

	config := koanf.New(".")

	_ = config.Load(confmap.Provider(map[string]interface{}{
		"server.port":        3000,
		"server.name":        "login.cacert.localhost",
		"server.key":         "certs/idp.cacert.localhost.key",
		"server.certificate": "certs/idp.cacert.localhost.crt.pem",
		"admin.url":          "https://hydra.cacert.localhost:4445/",
		"i18n.languages":     []string{"en", "de"},
	}, "."), nil)
	cFiles, _ := f.GetStringSlice("conf")
	for _, c := range cFiles {
		if err := config.Load(file.Provider(c), toml.Parser()); err != nil {
			logger.Fatalf("error loading config file: %s", err)
		}
	}
	if err := config.Load(posflag.Provider(f, ".", config), nil); err != nil {
		logger.Fatalf("error loading configuration: %s", err)
	}
	const prefix = "IDP_"
	if err := config.Load(env.Provider(prefix, ".", func(s string) string {
		return strings.Replace(strings.ToLower(
			strings.TrimPrefix(s, prefix)), "_", ".", -1)
	}), nil); err != nil {
		log.Fatalf("error loading config: %v", err)
	}

	logger.Infoln("Server is starting")
	ctx := context.Background()

	ctx = commonServices.InitI18n(ctx, logger, config.Strings("i18n.languages"))
	services.AddMessages(ctx)

	adminURL, err := url.Parse(config.MustString("admin.url"))
	if err != nil {
		logger.Fatalf("error parsing admin URL: %v", err)
	}
	clientTransport := client.New(adminURL.Host, adminURL.Path, []string{adminURL.Scheme})
	adminClient := hydra.New(clientTransport, nil)

	handlerContext := context.WithValue(ctx, handlers.CtxAdminClient, adminClient.Admin)
	loginHandler, err := handlers.NewLoginHandler(handlerContext, logger)
	if err != nil {
		logger.Fatalf("error initializing login handler: %v", err)
	}
	consentHandler, err := handlers.NewConsentHandler(handlerContext, logger)
	if err != nil {
		logger.Fatalf("error initializing consent handler: %v", err)
	}
	logoutHandler := handlers.NewLogoutHandler(logger, handlerContext)
	logoutSuccessHandler := handlers.NewLogoutSuccessHandler()
	errorHandler := handlers.NewErrorHandler()

	router := http.NewServeMux()
	router.Handle("/login", loginHandler)
	router.Handle("/consent", consentHandler)
	router.Handle("/logout", logoutHandler)
	router.Handle("/error", errorHandler)
	router.Handle("/logout-successful", logoutSuccessHandler)
	router.Handle("/health", commonHandlers.NewHealthHandler())

	if err != nil {
		logger.Fatal(err)
	}

	csrfKey, err := base64.StdEncoding.DecodeString(config.MustString("security.csrf.key"))
	if err != nil {
		logger.Fatalf("could not parse CSRF key bytes: %v", err)
	}

	nextRequestId := func() string {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}

	tracing := commonHandlers.Tracing(nextRequestId)
	logging := commonHandlers.Logging(logger)
	hsts := commonHandlers.EnableHSTS()
	csrfProtect := csrf.Protect(
		csrfKey,
		csrf.Secure(true),
		csrf.SameSite(csrf.SameSiteStrictMode),
		csrf.MaxAge(600))

	tlsConfig := &tls.Config{
		ServerName: config.String("server.name"),
		MinVersion: tls.VersionTLS12,
	}
	server := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", config.String("server.name"), config.Int("server.port")),
		Handler:      tracing(logging(hsts(csrfProtect(router)))),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  15 * time.Second,
		TLSConfig:    tlsConfig,
	}

	done := make(chan bool)
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)

	go func() {
		<-quit
		logger.Infoln("Server is shutting down...")
		atomic.StoreInt32(&commonHandlers.Healthy, 0)

		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		server.SetKeepAlivesEnabled(false)
		if err := server.Shutdown(ctx); err != nil {
			logger.Fatalf("Could not gracefully shutdown the server: %v\n", err)
		}
		close(done)
	}()

	logger.Infof("Server is ready to handle requests at https://%s/", server.Addr)
	atomic.StoreInt32(&commonHandlers.Healthy, 1)
	if err := server.ListenAndServeTLS(
		config.String("server.certificate"), config.String("server.key"),
	); err != nil && err != http.ErrServerClosed {
		logger.Fatalf("Could not listen on %s: %v\n", server.Addr, err)
	}

	<-done
	logger.Infoln("Server stopped")
}
