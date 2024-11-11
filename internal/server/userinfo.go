package server

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/ophum/github-teams-oauth2/ent"
	"github.com/ophum/github-teams-oauth2/ent/accesstoken"
)

func (s *Server) getUserinfoHandle(ctx echo.Context) error {
	token, err := getBearerToken(ctx.Request().Header)
	if err != nil {
		return echo.ErrUnauthorized
	}

	hashedToken := sha512String(token)
	accessToken, err := s.db.AccessToken.Query().
		Where(accesstoken.Token(hashedToken)).
		First(ctx.Request().Context())
	if err != nil {
		return err
	}

	user, err := accessToken.QueryUser().First(ctx.Request().Context())
	if err != nil {
		return err
	}

	groups, err := accessToken.QueryGroups().All(ctx.Request().Context())
	if err != nil {
		return err
	}

	ret := map[string]any{
		"id":       user.ID.String(),
		"username": user.Name,
		"email":    user.Email,
	}
	if len(groups) > 0 {
		ret["groups"] = slicesMap(groups, func(v *ent.Group) string {
			return v.Name
		})
	}
	return ctx.JSON(http.StatusOK, ret)
}
