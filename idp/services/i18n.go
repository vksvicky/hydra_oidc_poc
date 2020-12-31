package services

import (
	"context"

	"github.com/BurntSushi/toml"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	log "github.com/sirupsen/logrus"
	"golang.org/x/text/language"
)

type contextKey int

const (
	CtxI18nBundle contextKey = iota
	CtxI18nCatalog
)

func InitI18n(ctx context.Context, logger *log.Logger) context.Context {
	bundle := i18n.NewBundle(language.English)
	bundle.RegisterUnmarshalFunc("toml", toml.Unmarshal)
	_, err := bundle.LoadMessageFile("de.toml")
	if err != nil {
		logger.Warnln("message bundle de.toml not found")
	}
	catalog := initMessageCatalog()
	ctx = context.WithValue(ctx, CtxI18nBundle, bundle)
	ctx = context.WithValue(ctx, CtxI18nCatalog, catalog)
	return ctx
}

func initMessageCatalog() map[string]*i18n.Message {
	messageCatalog := make(map[string]*i18n.Message)
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
	return messageCatalog
}
