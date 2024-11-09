package server

import (
	"fmt"
	"net/http"
	"slices"

	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/ophum/github-teams-oauth2/ent"
	"github.com/ophum/github-teams-oauth2/ent/group"
	"github.com/ophum/github-teams-oauth2/ent/user"
)

func (s *Server) getOauth2GithubCallbackHandle(ctx echo.Context) error {
	sess, err := session.Get("session", ctx)
	if err != nil {
		return err
	}

	var callbackParams struct {
		Code  string `query:"code"`
		State string `query:"state"`
	}
	if err := ctx.Bind(&callbackParams); err != nil {
		return err
	}

	sessionState, ok := sess.Values["github_state_"+callbackParams.State].(map[string]string)
	if !ok {
		return ctx.String(http.StatusBadRequest, "invalid state")
	}

	token, err := s.oauth2Config.Exchange(ctx.Request().Context(), callbackParams.Code)
	if err != nil {
		return err
	}

	githubName, err := s.getGithubUser(ctx.Request().Context(), token)
	if err != nil {
		return err
	}
	email, err := s.getGithubUserEmail(ctx.Request().Context(), token)
	if err != nil {
		return err
	}

	orgTeams, err := s.getGithubOrgTeams(ctx.Request().Context(), token)
	if err != nil {
		return err
	}

	ret := []string{email}
	for org, teams := range orgTeams {
		for _, team := range teams {
			ret = append(ret, fmt.Sprintf("%s:%s", org, team))
		}
	}

	ret = slices.DeleteFunc(ret, func(v string) bool {
		return !slices.Contains(s.config.Github.AvailableOrgTeams, v)
	})
	slices.Sort(ret)

	user, err := s.db.User.Query().Where(user.Name(email)).First(ctx.Request().Context())
	if err != nil {
		if !ent.IsNotFound(err) {
			return err
		}

		user, err = s.db.User.Create().
			SetName(githubName).
			SetEmail(email).
			Save(ctx.Request().Context())
		if err != nil {
			return err
		}
	}

	builders := []*ent.GroupCreate{}
	for _, group := range ret {
		builders = append(builders, s.db.Group.Create().SetName(group))
	}
	if err := s.db.Group.CreateBulk(builders...).
		OnConflictColumns(group.FieldName).
		DoNothing().
		UpdateNewValues().
		Exec(ctx.Request().Context()); err != nil {
		return err
	}

	dgroups, err := s.db.Group.Query().Where(group.NameIn(ret...)).All(ctx.Request().Context())
	if err != nil {
		return err
	}

	user, err = user.Update().AddGroups(dgroups...).Save(ctx.Request().Context())
	if err != nil {
		return err
	}

	sess.Values["user_id"] = user.ID.String()
	sess.Values["access_token"] = token.AccessToken
	if err := sess.Save(ctx.Request(), ctx.Response()); err != nil {
		return err
	}

	return ctx.Redirect(http.StatusSeeOther, sessionState["return"])
}
