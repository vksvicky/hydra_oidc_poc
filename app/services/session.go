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
