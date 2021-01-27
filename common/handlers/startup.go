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
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"time"

	"github.com/knadh/koanf"
	"github.com/sirupsen/logrus"
)

func StartApplication(logger *logrus.Logger, ctx context.Context, server *http.Server, config *koanf.Koanf) {
	done := make(chan bool)
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)

	go func() {
		<-quit
		logger.Infoln("Server is shutting down...")
		atomic.StoreInt32(&Healthy, 0)

		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		server.SetKeepAlivesEnabled(false)
		if err := server.Shutdown(ctx); err != nil {
			logger.Fatalf("Could not gracefully shutdown the server: %v\n", err)
		}
		close(done)
	}()

	logger.Infof("Server is ready to handle requests at https://%s/", server.Addr)
	atomic.StoreInt32(&Healthy, 1)
	if err := server.ListenAndServeTLS(
		config.String("server.certificate"), config.String("server.key"),
	); err != nil && err != http.ErrServerClosed {
		logger.Fatalf("Could not listen on %s: %v\n", server.Addr, err)
	}

	<-done
	logger.Infoln("Server stopped")
}
