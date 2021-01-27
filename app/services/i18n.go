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
