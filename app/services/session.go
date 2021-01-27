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

package services

import (
	"os"

	"github.com/gorilla/sessions"
	log "github.com/sirupsen/logrus"
)

var store *sessions.FilesystemStore

func InitSessionStore(logger *log.Logger, sessionPath string, keys ...[]byte) {
	store = sessions.NewFilesystemStore(sessionPath, keys...)
	if _, err := os.Stat(sessionPath); err != nil {
		if os.IsNotExist(err) {
			if err = os.MkdirAll(sessionPath, 0700); err != nil {
				logger.Fatalf("could not create session store directory: %s", err)
			}
		}
	}
}

func GetSessionStore() *sessions.FilesystemStore {
	return store
}
