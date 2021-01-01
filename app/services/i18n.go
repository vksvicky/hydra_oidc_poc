package services

import (
	"context"

	"github.com/nicksnyder/go-i18n/v2/i18n"

	"git.cacert.org/oidc_login/common/services"
)

func AddMessages(ctx context.Context) {
	messages := make(map[string]*i18n.Message)
	messages["IndexGreeting"] = &i18n.Message{
		ID:    "IndexGreeting",
		Other: "Hello {{ .User }}",
	}
	messages["IndexTitle"] = &i18n.Message{
		ID:    "IndexTitle",
		Other: "Welcome to the Demo application",
	}
	messages["LogoutLabel"] = &i18n.Message{
		ID:          "LogoutLabel",
		Description: "A label on a logout button or link",
		Other:       "Logout",
	}
	messages["IndexIntroductionText"] = &i18n.Message{
		ID:    "IndexIntroductionText",
		Other: "This is an authorization protected resource",
	}
	services.GetMessageCatalog(ctx).AddMessages(messages)
}
