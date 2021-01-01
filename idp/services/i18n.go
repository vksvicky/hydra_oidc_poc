package services

import (
	"context"

	"github.com/nicksnyder/go-i18n/v2/i18n"

	"git.cacert.org/oidc_login/common/services"
)

func AddMessages(ctx context.Context) {
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
	services.GetMessageCatalog(ctx).AddMessages(messages)
}
