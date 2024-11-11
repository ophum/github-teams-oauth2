package server

import (
	"net/http"

	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
)

func (s *Server) getSignIn(ctx echo.Context) error {
	sess, err := session.Get("session", ctx)
	if err != nil {
		return err
	}
	_, isAuthed := sess.Values["user_id"].(string)

	if !isAuthed {
		sess.Options = &sessions.Options{
			Path:     "/",
			HttpOnly: true,
			Secure:   false,
		}
		if err := sess.Save(ctx.Request(), ctx.Response()); err != nil {
			return err
		}
	}
	redirectURI := ctx.QueryParam("redirect_uri")
	return render(ctx, http.StatusOK, "sign-in", map[string]any{
		"RedirectURI": redirectURI,
		"IsAuthed":    isAuthed,
	})
}

func (s *Server) postSignIn(ctx echo.Context) error {
	sess, err := session.Get("session", ctx)
	if err != nil {
		return err
	}

	redirectURI := ctx.FormValue("redirect_uri")
	if redirectURI == "" {
		redirectURI = "/sign-in"
	}

	state, err := randomString(32)
	if err != nil {
		return err
	}
	sess.Values["github_state_"+state] = map[string]string{
		"return": redirectURI,
	}

	sess.Options = &sessions.Options{
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
	}
	if err := sess.Save(ctx.Request(), ctx.Response()); err != nil {
		return err
	}

	url := s.oauth2Config.AuthCodeURL(state)

	return ctx.Redirect(http.StatusFound, url)
}

func (s *Server) postSignOut(ctx echo.Context) error {
	sess, err := session.Get("session", ctx)
	if err != nil {
		return err
	}

	sess.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	}
	if err := sess.Save(ctx.Request(), ctx.Response()); err != nil {
		return err
	}

	return ctx.Redirect(http.StatusFound, "/sign-in")
}
