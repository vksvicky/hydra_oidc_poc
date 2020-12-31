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
	CtxI18nBundle contextKey = iota
	CtxI18nCatalog
)

type MessageCatalog struct {
	messages map[string]*i18n.Message
	logger   *log.Logger
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
				m.logger.Error("no default translation found")
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
		return id
	}
}

func InitI18n(ctx context.Context, logger *log.Logger) context.Context {
	bundle := i18n.NewBundle(language.English)
	bundle.RegisterUnmarshalFunc("toml", toml.Unmarshal)
	_, err := bundle.LoadMessageFile("de.toml")
	if err != nil {
		logger.Warnln("message bundle de.toml not found")
	}
	catalog := initMessageCatalog(logger)
	ctx = context.WithValue(ctx, CtxI18nBundle, bundle)
	ctx = context.WithValue(ctx, CtxI18nCatalog, catalog)
	return ctx
}

func initMessageCatalog(logger *log.Logger) *MessageCatalog {
	messages := make(map[string]*i18n.Message)
	messages["unknown"] = &i18n.Message{
		ID:    "ErrorUnknown",
		Other: "Unknown error",
	}
	messages["email"] = &i18n.Message{
		ID:    "ErrorEmail",
		Other: "Please enter a valid email address.",
	}
	messages["Email-required"] = &i18n.Message{
		ID:    "ErrorEmailRequired",
		Other: "Please enter an email address.",
	}
	messages["required"] = &i18n.Message{
		ID:    "ErrorRequired",
		Other: "Please enter a value",
	}
	messages["Password-required"] = &i18n.Message{
		ID:    "ErrorPasswordRequired",
		Other: "Please enter a password.",
	}
	messages["TitleRequestConsent"] = &i18n.Message{
		ID:    "TitleRequestConsent",
		Other: "Application requests your consent",
	}
	messages["LabelSubmit"] = &i18n.Message{
		ID:    "LabelSubmit",
		Other: "Submit",
	}
	messages["LabelConsent"] = &i18n.Message{
		ID:    "LabelConsent",
		Other: "I hereby agree that the application may get the requested permissions.",
	}
	messages["IntroConsentRequested"] = &i18n.Message{
		ID:    "IntroConsentRequested",
		Other: "The <strong>{{ .client }}</strong> application wants your consent for the requested set of permissions.",
	}
	messages["IntroConsentMoreInformation"] = &i18n.Message{
		ID:    "IntroConsentMoreInformation",
		Other: "You can find more information about <strong>{{ .client }}</strong> at <a href=\"{{ .clientLink }}\">its description page</a>.",
	}
	messages["Scope-openid-Description"] = &i18n.Message{
		ID:    "Scope-openid-Description",
		Other: "Request information about your identity.",
	}
	messages["Scope-offline_access-Description"] = &i18n.Message{
		ID:    "Scope-offline_access-Description",
		Other: "Keep access to your information until you revoke the permission.",
	}
	messages["Scope-profile-Description"] = &i18n.Message{
		ID:    "Scope-profile-Description",
		Other: "Access your user profile information including your name, birth date and locale.",
	}
	messages["Scope-email-Description"] = &i18n.Message{
		ID:    "Scope-email-Description",
		Other: "Access your primary email address.",
	}
	return &MessageCatalog{messages: messages, logger: logger}
}
