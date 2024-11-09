package server

import "github.com/google/uuid"

type ResponseType string

const (
	ResponseTypeCode ResponseType = "code"
)

type BeginAuthorizeRequest struct {
	ResponseType ResponseType `query:"response_type"`
	ClientID     string       `query:"client_id"`
	Scope        string       `query:"scope"`
	RedirectURI  string       `query:"redirect_uri"`
	State        string       `query:"state"`
}

type PostAuthorizeRequest struct {
	RequestID string      `form:"request_id"`
	GroupIDs  []uuid.UUID `form:"group_ids[]"`
}

type GrantType string

const (
	GrantTypeAuthorizationCode GrantType = "authorization_code"
)

type TokenRequest struct {
	GrantType   GrantType `form:"grant_type"`
	Code        string    `form:"code"`
	RedirectURI string    `form:"redirect_uri"`
	ClientID    string    `form:"client_id"`
}
