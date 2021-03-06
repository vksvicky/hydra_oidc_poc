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
		Other: "The <strong>{{ .client }}</strong> application requested your consent for the following set of permissions:",
	}
	messages["IntroConsentMoreInformation"] = &i18n.Message{
		ID:    "IntroConsentMoreInformation",
		Other: "You can find more information about <strong>{{ .client }}</strong> at <a href=\"{{ .clientLink }}\">its description page</a>.",
	}
	messages["ClaimsInformation"] = &i18n.Message{
		ID:    "ClaimsInformation",
		Other: "In addition the application wants access to the following information:",
	}
	messages["WrongOrLockedUserOrInvalidPassword"] = &i18n.Message{
		ID:    "WrongOrLockedUserOrInvalidPassword",
		Other: "You entered an invalid username or password or your account has been locked.",
	}
	messages["LoginTitle"] = &i18n.Message{
		ID:    "LoginTitle",
		Other: "Login",
	}
	messages["LabelEmail"] = &i18n.Message{
		ID:          "FormLabelEmail",
		Description: "Label for an email form field",
		Other:       "Email:",
	}
	messages["LabelPassword"] = &i18n.Message{
		ID:          "FormLabelPassword",
		Description: "Label for a password form field",
		Other:       "Password:",
	}
	messages["LabelLogin"] = &i18n.Message{
		ID:          "LabelLogin",
		Description: "Label for a login button",
		Other:       "Login",
	}
	messages["CertLoginIntroText"] = &i18n.Message{
		ID:    "CertLoginIntroText",
		Other: "You have presented a valid client certificate for the following email addresses:",
	}
	messages["CertLoginRequestText"] = &i18n.Message{
		ID:    "CertLoginRequestText",
		Other: "Do you want to use this certificate for authentication or do you want to use a different method?",
	}
	messages["LabelAcceptCertLogin"] = &i18n.Message{
		ID:          "LabelAcceptCertLogin",
		Description: "Label for a button to accept certificate login",
		Other:       "Yes, please use the certificate",
	}
	messages["LabelRejectCertLogin"] = &i18n.Message{
		ID:          "LabelRejectCertLogin",
		Description: "Label for a button to reject certificate login",
		Other:       "No, please ask for my password",
	}
	services.GetMessageCatalog(ctx).AddMessages(messages)
}
