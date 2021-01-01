package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"time"

	"github.com/knadh/koanf"
	"github.com/knadh/koanf/parsers/toml"
	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/providers/posflag"
	log "github.com/sirupsen/logrus"
	flag "github.com/spf13/pflag"

	"git.cacert.org/oidc_login/app/handlers"
	"git.cacert.org/oidc_login/app/services"
	commonHandlers "git.cacert.org/oidc_login/common/handlers"
	commonServices "git.cacert.org/oidc_login/common/services"
)

func main() {
	f := flag.NewFlagSet("config", flag.ContinueOnError)
	f.Usage = func() {
		fmt.Println(f.FlagUsages())
		os.Exit(0)
	}
	f.StringSlice("conf", []string{"resource_app.toml"}, "path to one or more .toml files")
	logger := log.New()
	var err error

	if err = f.Parse(os.Args[1:]); err != nil {
		logger.Fatal(err)
	}

	config := koanf.New(".")

	_ = config.Load(confmap.Provider(map[string]interface{}{
		"server.port":        4000,
		"server.name":        "app.cacert.localhost",
		"server.key":         "certs/app.cacert.localhost.key",
		"server.certificate": "certs/app.cacert.localhost.crt.pem",
		"oidc.server":        "https://auth.cacert.localhost:4444/",
		"session.path":       "sessions/app",
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
	if err := config.Load(file.Provider("resource_app.toml"), toml.Parser()); err != nil && !os.IsNotExist(err) {
		log.Fatalf("error loading config: %v", err)
	}
	const prefix = "RESOURCE_APP_"
	if err := config.Load(env.Provider(prefix, ".", func(s string) string {
		return strings.Replace(strings.ToLower(
			strings.TrimPrefix(s, prefix)), "_", ".", -1)
	}), nil); err != nil {
		log.Fatalf("error loading config: %v", err)
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

	tlsConfig := &tls.Config{
		ServerName: config.String("server.name"),
		MinVersion: tls.VersionTLS12,
	}
	server := &http.Server{
		Addr:         serverAddr,
		Handler:      tracing(logging(hsts(router))),
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
