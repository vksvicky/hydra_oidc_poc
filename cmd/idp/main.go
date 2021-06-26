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

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sync/atomic"
	"time"

	"github.com/go-openapi/runtime/client"
	"github.com/gorilla/csrf"
	hydra "github.com/ory/hydra-client-go/client"
	log "github.com/sirupsen/logrus"

	commonHandlers "git.cacert.org/oidc_login/common/handlers"
	commonServices "git.cacert.org/oidc_login/common/services"
	"git.cacert.org/oidc_login/idp/handlers"
	"git.cacert.org/oidc_login/idp/services"
)

func main() {
	logger := log.New()
	config, err := commonServices.ConfigureApplication(
		logger,
		"IDP",
		map[string]interface{}{
			"server.port":             3000,
			"server.name":             "login.cacert.localhost",
			"server.key":              "certs/idp.cacert.localhost.key",
			"server.certificate":      "certs/idp.cacert.localhost.crt.pem",
			"security.client.ca-file": "certs/client_ca.pem",
			"admin.url":               "https://hydra.cacert.localhost:4445/",
			"i18n.languages":          []string{"en", "de"},
		})
	if err != nil {
		log.Fatalf("error loading configuration: %v", err)
	}

	logger.Infoln("Server is starting")
	ctx := context.Background()

	ctx = commonServices.InitI18n(ctx, logger, config.Strings("i18n.languages"))
	services.AddMessages(ctx)

	adminURL, err := url.Parse(config.MustString("admin.url"))
	if err != nil {
		logger.Fatalf("error parsing admin URL: %v", err)
	}
	tlsClientConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if config.Exists("api-client.rootCAs") {
		rootCAFile := config.MustString("api-client.rootCAs")
		caCertPool := x509.NewCertPool()
		pemBytes, err := ioutil.ReadFile(rootCAFile)
		if err != nil {
			log.Fatalf("could not read CA certificate file: %v", err)
		}
		caCertPool.AppendCertsFromPEM(pemBytes)
		tlsClientConfig.RootCAs = caCertPool
	}

	tlsClientTransport := &http.Transport{TLSClientConfig: tlsClientConfig}
	httpClient := &http.Client{Transport: tlsClientTransport}
	clientTransport := client.NewWithClient(
		adminURL.Host,
		adminURL.Path,
		[]string{adminURL.Scheme},
		httpClient,
	)
	adminClient := hydra.New(clientTransport, nil)

	ctx, err = services.InitDatabase(ctx, services.NewDatabaseParams(config.MustString("db.dsn")))
	if err != nil {
		logger.Fatalf("error initializing the database connection: %v", err)
	}

	handlerContext := context.WithValue(ctx, handlers.CtxAdminClient, adminClient.Admin)
	loginHandler, err := handlers.NewLoginHandler(handlerContext, logger)
	if err != nil {
		logger.Fatalf("error initializing login handler: %v", err)
	}
	consentHandler, err := handlers.NewConsentHandler(handlerContext, logger)
	if err != nil {
		logger.Fatalf("error initializing consent handler: %v", err)
	}
	logoutHandler := handlers.NewLogoutHandler(handlerContext, logger)
	logoutSuccessHandler := handlers.NewLogoutSuccessHandler()
	errorHandler := handlers.NewErrorHandler()
	staticFiles := http.FileServer(http.Dir("static"))

	router := http.NewServeMux()
	router.Handle("/login", loginHandler)
	router.Handle("/consent", consentHandler)
	router.Handle("/logout", logoutHandler)
	router.Handle("/error", errorHandler)
	router.Handle("/logout-successful", logoutSuccessHandler)
	router.Handle("/health", commonHandlers.NewHealthHandler())
	router.Handle("/images/", staticFiles)
	router.Handle("/css/", staticFiles)
	router.Handle("/js/", staticFiles)

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
	errorMiddleware, err := commonHandlers.ErrorHandling(
		ctx,
		logger,
		"templates/idp",
	)
	if err != nil {
		logger.Fatalf("could not initialize request error handling: %v", err)
	}

	clientCertPool := x509.NewCertPool()
	pemBytes, err := ioutil.ReadFile(config.MustString("security.client.ca-file"))
	if err != nil {
		logger.Fatalf("could not load client CA certificates: %v", err)
	}
	clientCertPool.AppendCertsFromPEM(pemBytes)

	tlsConfig := &tls.Config{
		ServerName: config.String("server.name"),
		MinVersion: tls.VersionTLS12,
		ClientAuth: tls.VerifyClientCertIfGiven,
		ClientCAs:  clientCertPool,
	}
	server := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", config.String("server.name"), config.Int("server.port")),
		Handler:      tracing(logging(hsts(errorMiddleware(csrfProtect(router))))),
		ReadTimeout:  20 * time.Second,
		WriteTimeout: 20 * time.Second,
		IdleTimeout:  30 * time.Second,
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
