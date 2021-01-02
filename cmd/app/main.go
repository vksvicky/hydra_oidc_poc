package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/knadh/koanf/parsers/toml"
	"github.com/knadh/koanf/providers/confmap"
	log "github.com/sirupsen/logrus"

	"git.cacert.org/oidc_login/app/handlers"
	"git.cacert.org/oidc_login/app/services"
	commonHandlers "git.cacert.org/oidc_login/common/handlers"
	commonServices "git.cacert.org/oidc_login/common/services"
)

func main() {
	logger := log.New()
	config, err := commonServices.ConfigureApplication(
		logger,
		"RESOURCE_APP",
		map[string]interface{}{
			"server.port":        4000,
			"server.name":        "app.cacert.localhost",
			"server.key":         "certs/app.cacert.localhost.key",
			"server.certificate": "certs/app.cacert.localhost.crt.pem",
			"oidc.server":        "https://auth.cacert.localhost:4444/",
			"session.path":       "sessions/app",
			"i18n.languages":     []string{"en", "de"},
		})
	if err != nil {
		log.Fatalf("error loading configuration: %v", err)
	}

	oidcServer := config.MustString("oidc.server")
	oidcClientId := config.MustString("oidc.client-id")
	oidcClientSecret := config.MustString("oidc.client-secret")

	ctx := context.Background()
	ctx = commonServices.InitI18n(ctx, logger, config.Strings("i18n.languages"))
	services.AddMessages(ctx)

	sessionPath := config.MustString("session.path")
	sessionAuthKey, err := base64.StdEncoding.DecodeString(config.String("session.auth-key"))
	if err != nil {
		log.Fatalf("could not decode session auth key: %s", err)
	}
	sessionEncKey, err := base64.StdEncoding.DecodeString(config.String("session.enc-key"))
	if err != nil {
		log.Fatalf("could not decode session encryption key: %s", err)
	}

	generated := false
	if len(sessionAuthKey) != 64 {
		sessionAuthKey = commonServices.GenerateKey(64)
		generated = true
	}
	if len(sessionEncKey) != 32 {
		sessionEncKey = commonServices.GenerateKey(32)
		generated = true
	}

	if generated {
		_ = config.Load(confmap.Provider(map[string]interface{}{
			"session.auth-key": sessionAuthKey,
			"session.enc-key":  sessionEncKey,
		}, "."), nil)
		tomlData, err := config.Marshal(toml.Parser())
		if err != nil {
			log.Fatalf("could not encode session config")
		}
		log.Infof("put the following in your resource_app.toml:\n%s", string(tomlData))
	}

	if ctx, err = commonServices.DiscoverOIDC(ctx, logger, &commonServices.OidcParams{
		OidcServer:       oidcServer,
		OidcClientId:     oidcClientId,
		OidcClientSecret: oidcClientSecret,
		APIClient:        &http.Client{},
	}); err != nil {
		log.Fatalf("OpenID Connect discovery failed: %s", err)
	}

	services.InitSessionStore(logger, sessionPath, sessionAuthKey, sessionEncKey)

	authMiddleware := handlers.Authenticate(ctx, oidcClientId)

	serverAddr := fmt.Sprintf("%s:%d", config.String("server.name"), config.Int("server.port"))

	indexHandler, err := handlers.NewIndexHandler(ctx, serverAddr)
	if err != nil {
		logger.Fatalf("could not initialize index handler: %v", err)
	}
	callbackHandler := handlers.NewCallbackHandler(ctx, logger)
	afterLogoutHandler := handlers.NewAfterLogoutHandler(logger)
	staticFiles := http.FileServer(http.Dir("static"))

	router := http.NewServeMux()
	router.Handle("/", authMiddleware(indexHandler))
	router.Handle("/callback", callbackHandler)
	router.Handle("/after-logout", afterLogoutHandler)
	router.Handle("/health", commonHandlers.NewHealthHandler())
	router.Handle("/images/", staticFiles)
	router.Handle("/css/", staticFiles)
	router.Handle("/js/", staticFiles)

	nextRequestId := func() string {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}

	tracing := commonHandlers.Tracing(nextRequestId)
	logging := commonHandlers.Logging(logger)
	hsts := commonHandlers.EnableHSTS()
	errorMiddleware, err := commonHandlers.ErrorHandling(
		ctx,
		logger,
		"templates/app",
	)
	if err != nil {
		logger.Fatalf("could not initialize request error handling: %v", err)
	}

	tlsConfig := &tls.Config{
		ServerName: config.String("server.name"),
		MinVersion: tls.VersionTLS12,
	}
	server := &http.Server{
		Addr:         serverAddr,
		Handler:      tracing(logging(hsts(errorMiddleware(router)))),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  15 * time.Second,
		TLSConfig:    tlsConfig,
	}

	commonHandlers.StartApplication(logger, ctx, server, config)
}
