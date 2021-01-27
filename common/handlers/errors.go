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
	"html/template"
	"net/http"
	"path"

	"github.com/nicksnyder/go-i18n/v2/i18n"
	log "github.com/sirupsen/logrus"

	commonServices "git.cacert.org/oidc_login/common/services"
)

type errorKey int

const (
	errorBucketKey errorKey = iota
)

type ErrorDetails struct {
	ErrorMessage string
	ErrorDetails []string
	ErrorCode    string
	Error        error
}

type ErrorBucket struct {
	errorDetails   *ErrorDetails
	templates      *template.Template
	logger         *log.Logger
	bundle         *i18n.Bundle
	messageCatalog *commonServices.MessageCatalog
}

func (b *ErrorBucket) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if b.errorDetails != nil {
		accept := r.Header.Get("Accept-Language")
		localizer := i18n.NewLocalizer(b.bundle, accept)
		err := b.templates.Lookup("base").Execute(w, map[string]interface{}{
			"Title": b.messageCatalog.LookupMessage(
				"ErrorTitle",
				nil,
				localizer,
			),
			"details": b.errorDetails,
		})
		if err != nil {
			log.Errorf("error rendering error template: %v", err)
			http.Error(
				w,
				http.StatusText(http.StatusInternalServerError),
				http.StatusInternalServerError,
			)
		}
	}
}

func GetErrorBucket(r *http.Request) *ErrorBucket {
	return r.Context().Value(errorBucketKey).(*ErrorBucket)
}

// call this from your application's handler
func (b *ErrorBucket) AddError(details *ErrorDetails) {
	b.errorDetails = details
}

type errorResponseWriter struct {
	http.ResponseWriter
	ctx        context.Context
	statusCode int
}

func (w *errorResponseWriter) WriteHeader(code int) {
	w.statusCode = code
	if code >= 400 {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		errorBucket := w.ctx.Value(errorBucketKey).(*ErrorBucket)
		if errorBucket != nil && errorBucket.errorDetails == nil {
			errorBucket.AddError(&ErrorDetails{
				ErrorMessage: http.StatusText(code),
			})
		}
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *errorResponseWriter) Write(content []byte) (int, error) {
	if w.statusCode > 400 {
		errorBucket := w.ctx.Value(errorBucketKey).(*ErrorBucket)
		if errorBucket != nil {
			if errorBucket.errorDetails.ErrorDetails == nil {
				errorBucket.errorDetails.ErrorDetails = make([]string, 0)
			}
			errorBucket.errorDetails.ErrorDetails = append(
				errorBucket.errorDetails.ErrorDetails, string(content),
			)
			return len(content), nil
		}
	}
	return w.ResponseWriter.Write(content)
}

func ErrorHandling(
	handlerContext context.Context,
	logger *log.Logger,
	templateBaseDir string,
) (func(http.Handler) http.Handler, error) {
	errorTemplates, err := template.ParseFiles(
		path.Join(templateBaseDir, "base.gohtml"),
		path.Join(templateBaseDir, "errors.gohtml"),
	)
	if err != nil {
		return nil, err
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			errorBucket := &ErrorBucket{
				templates:      errorTemplates,
				logger:         logger,
				bundle:         commonServices.GetI18nBundle(handlerContext),
				messageCatalog: commonServices.GetMessageCatalog(handlerContext),
			}
			ctx := context.WithValue(r.Context(), errorBucketKey, errorBucket)
			interCeptingResponseWriter := &errorResponseWriter{
				w,
				ctx,
				http.StatusOK,
			}
			next.ServeHTTP(
				interCeptingResponseWriter,
				r.WithContext(ctx),
			)
			errorBucket.serveHTTP(w, r)
		})
	}, nil
}
