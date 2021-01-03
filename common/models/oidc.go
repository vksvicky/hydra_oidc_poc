/*
This package contains data models.
*/
package models

// An individual claim request.
//
// Specification
//
// https://openid.net/specs/openid-connect-core-1_0.html#IndividualClaimsRequests
type IndividualClaimRequest map[string]interface{}

// ClaimElement represents a claim element
type ClaimElement map[string]*IndividualClaimRequest

// OIDCClaimsRequest the claims request parameter sent with the authorization request.
//
// Specification
//
// https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter
type OIDCClaimsRequest map[string]ClaimElement

// GetUserInfo extracts the userinfo claim element from the request.
//
// Specification
//
// https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims
//
// Requests that the listed individual Claims be returned from the UserInfo
// Endpoint. If present, the listed Claims are being requested to be added to
// any Claims that are being requested using scope values. If not present, the
// Claims being requested from the UserInfo Endpoint are only those requested
// using scope values.
//
// When the userinfo member is used, the request MUST also use a response_type
// value that results in an Access Token being issued to the Client for use at
// the UserInfo Endpoint.
func (r OIDCClaimsRequest) GetUserInfo() *ClaimElement {
	if userInfo, ok := r["userinfo"]; ok {
		return &userInfo
	}
	return nil
}

// GetIDToken extracts the id_token claim element from the request.
//
// Specification
//
// https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims
//
// Requests that the listed individual Claims be returned in the ID Token. If
// present, the listed Claims are being requested to be added to the default
// Claims in the ID Token. If not present, the default ID Token Claims are
// requested, as per the ID Token definition in Section 2 and per the
// additional per-flow ID Token requirements in Sections 3.1.3.6, 3.2.2.10,
// 3.3.2.11, and 3.3.3.6.
func (r OIDCClaimsRequest) GetIDToken() *ClaimElement {
	if idToken, ok := r["id_token"]; ok {
		return &idToken
	}
	return nil
}

// Checks whether the individual claim is an essential claim.
//
// Specification
//
// https://openid.net/specs/openid-connect-core-1_0.html#IndividualClaimsRequests
//
// Indicates whether the Claim being requested is an Essential Claim. If the
// value is true, this indicates that the Claim is an Essential Claim. For
// instance, the Claim request:
//
//   "auth_time": {"essential": true}
//
// can be used to specify that it is Essential to return an auth_time Claim
// Value. If the value is false, it indicates that it is a Voluntary Claim.
// The default is false.
//
// By requesting Claims as Essential Claims, the RP indicates to the End-User
// that releasing these Claims will ensure a smooth authorization for the
// specific task requested by the End-User.
//
// Note that even if the Claims are not available because the End-User did not
// authorize their release or they are not present, the Authorization Server
// MUST NOT generate an error when Claims are not returned, whether they are
// Essential or Voluntary, unless otherwise specified in the description of
// the specific claim.
func (i IndividualClaimRequest) IsEssential() bool {
	if essential, ok := i["essential"]; ok {
		return essential.(bool)
	}
	return false
}

// Returns the wanted value for an individual claim request.
//
// Specification
//
// https://openid.net/specs/openid-connect-core-1_0.html#IndividualClaimsRequests
//
// Requests that the Claim be returned with a particular value. For instance
// the Claim request:
//
//   "sub": {"value": "248289761001"}
//
// can be used to specify that the request apply to the End-User with Subject
// Identifier 248289761001. The value of the value member MUST be a valid
// value for the Claim being requested. Definitions of individual Claims can
// include requirements on how and whether the value qualifier is to be used
// when requesting that Claim.
func (i IndividualClaimRequest) WantedValue() *string {
	if value, ok := i["value"]; ok {
		valueString := value.(string)
		return &valueString
	}
	return nil
}

// Get the allowed values for an individual claim request that specifies
// a values field.
//
// Specification
//
// https://openid.net/specs/openid-connect-core-1_0.html#IndividualClaimsRequests
//
// Requests that the Claim be returned with one of a set of values, with the
// values appearing in order of preference. For instance the Claim request:
//
//   "acr": {"essential": true,
//           "values": ["urn:mace:incommon:iap:silver",
//                      "urn:mace:incommon:iap:bronze"]}
//
// specifies that it is Essential that the acr Claim be returned with either
// the value urn:mace:incommon:iap:silver or urn:mace:incommon:iap:bronze.
// The values in the values member array MUST be valid values for the Claim
// being requested. Definitions of individual Claims can include requirements
// on how and whether the values qualifier is to be used when requesting that
// Claim.
func (i IndividualClaimRequest) AllowedValues() []string {
	if values, ok := i["values"]; ok {
		return values.([]string)
	}
	return nil
}

// OpenIDConfiguration contains the parts of the OpenID discovery information
// that are relevant for us.
//
// Specification
//
// See https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
type OpenIDConfiguration struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JwksUri               string `json:"jwks_uri"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
}
