package services

import (
	"context"
	"fmt"

	"github.com/BurntSushi/toml"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	log "github.com/sirupsen/logrus"
	"golang.org/x/text/language"
)

type contextKey int

const (
	ctxI18nBundle contextKey = iota
	ctxI18nCatalog
)

type MessageCatalog struct {
	messages map[string]*i18n.Message
	logger   *log.Logger
}

func (m *MessageCatalog) AddMessages(messages map[string]*i18n.Message) {
	for key, value := range messages {
		m.messages[key] = value
	}
}

func (m *MessageCatalog) LookupErrorMessage(tag string, field string, value interface{}, localizer *i18n.Localizer) string {
	var message *i18n.Message
	message, ok := m.messages[fmt.Sprintf("%s-%s", field, tag)]
	if !ok {
		m.logger.Infof("no specific error message %s-%s", field, tag)
		message, ok = m.messages[tag]
		if !ok {
			m.logger.Infof("no specific error message %s", tag)
			message, ok = m.messages["unknown"]
			if !ok {
				m.logger.Warnf("no default translation found")
				return tag
			}
		}
	}

	translation, err := localizer.Localize(&i18n.LocalizeConfig{
		DefaultMessage: message,
		TemplateData: map[string]interface{}{
			"Value": value,
		},
	})
	if err != nil {
		m.logger.Error(err)
		return tag
	}
	return translation
}

func (m *MessageCatalog) LookupMessage(id string, templateData map[string]interface{}, localizer *i18n.Localizer) string {
	if message, ok := m.messages[id]; ok {
		translation, err := localizer.Localize(&i18n.LocalizeConfig{
			DefaultMessage: message,
			TemplateData:   templateData,
		})
		if err != nil {
			m.logger.Error(err)
			return id
		}
		return translation
	} else {
		m.logger.Warnf("no translation found for %s", id)
		return id
	}
}

func InitI18n(ctx context.Context, logger *log.Logger, languages []string) context.Context {
	bundle := i18n.NewBundle(language.English)
	bundle.RegisterUnmarshalFunc("toml", toml.Unmarshal)
	for _, lang := range languages {
		_, err := bundle.LoadMessageFile(fmt.Sprintf("active.%s.toml", lang))
		if err != nil {
			logger.Warnln("message bundle de.toml not found")
		}
	}
	catalog := initMessageCatalog(logger)
	ctx = context.WithValue(ctx, ctxI18nBundle, bundle)
	ctx = context.WithValue(ctx, ctxI18nCatalog, catalog)
	return ctx
}

func initMessageCatalog(logger *log.Logger) *MessageCatalog {
	messages := make(map[string]*i18n.Message)
	messages["ErrorTitle"] = &i18n.Message{
		ID:    "ErrorTitle",
		Other: "An error has occurred",
	}
	return &MessageCatalog{messages: messages, logger: logger}
}

func GetI18nBundle(ctx context.Context) *i18n.Bundle {
	return ctx.Value(ctxI18nBundle).(*i18n.Bundle)
}

func GetMessageCatalog(ctx context.Context) *MessageCatalog {
	return ctx.Value(ctxI18nCatalog).(*MessageCatalog)
}
