package server

import (
	"crypto/subtle"
	"encoding/gob"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/ophum/github-teams-oauth2/ent"
	"github.com/ophum/github-teams-oauth2/ent/accesstoken"
	"github.com/ophum/github-teams-oauth2/ent/code"
	"github.com/ophum/github-teams-oauth2/ent/group"
	"github.com/ophum/github-teams-oauth2/ent/user"
	"github.com/ophum/github-teams-oauth2/internal/config"
	"golang.org/x/oauth2"
	"gopkg.in/boj/redistore.v1"
)

func init() {
	gob.Register(map[string]string{})
}

type Template struct {
	templates *template.Template
}

func (t *Template) Render(w io.Writer, name string, data any, c echo.Context) error {
	return t.templates.ExecuteTemplate(w, name, data)
}

type Server struct {
	db           *ent.Client
	config       *config.Config
	sessionStore *redistore.RediStore
	oauth2Config *oauth2.Config
}

func New(conf *config.Config) (*Server, error) {
	db, err := conf.Database.Open()
	if err != nil {
		return nil, err
	}
	store, err := conf.Session.Redis.Open()
	if err != nil {
		return nil, err
	}

	return &Server{
		db:           db,
		config:       conf,
		sessionStore: store,
		oauth2Config: conf.Github.OAuth2Config(),
	}, nil
}

func (s *Server) Shutdown() error {
	if err := s.db.Close(); err != nil {
		return err
	}
	if err := s.sessionStore.Close(); err != nil {
		return err
	}
	return nil
}

func (s *Server) Run() error {
	t := &Template{
		templates: template.Must(template.ParseGlob("views/*.html")),
	}

	e := echo.New()
	e.Renderer = t
	e.Use(middleware.Logger())

	withSession := e.Group("",
		session.Middleware(s.sessionStore),
		middleware.CSRFWithConfig(middleware.CSRFConfig{
			TokenLookup: "form:_csrf",
		}))
	withSession.GET("/oauth2/authorize", s.getOauth2AuthorizeHandle)
	withSession.POST("/oauth2/authorize", s.postOauth2AuthorizeHandle)
	withSession.GET("/oauth2/github/callback", s.getOauth2GithubCallbackHandle)

	e.POST("/oauth2/token", s.postOauth2TokenHandle)
	e.GET("/userinfo", s.getUserinfoHandle)

	e.Logger.Fatal(e.Start(":8080"))
	return nil
}

func (s *Server) getOauth2AuthorizeHandle(ctx echo.Context) error {
	sess, err := session.Get("session", ctx)
	if err != nil {
		return err
	}

	var req struct {
		ResponseType string `query:"response_type"`
		ClientID     string `query:"client_id"`
		RedirectURI  string `query:"redirect_uri"`
		State        string `query:"state"`
	}
	if err := ctx.Bind(&req); err != nil {
		return err
	}

	if req.ResponseType != "code" {
		return errors.New("invalid response_type")
	}

	if req.ClientID != s.config.Oauth2.ClientID {
		return errors.New("invalid client_id'")
	}
	sess.Values["client_id"] = req.ClientID
	sess.Values["state"] = req.State
	if err := sess.Save(ctx.Request(), ctx.Response()); err != nil {
		return err
	}

	userID, ok := sess.Values["user_id"].(string)
	if !ok {
		log.Println("unauthorized, begin github oauth")
		return s.redirectGithubOAuth2(ctx, sess)
	}
	user, err := s.db.User.Get(ctx.Request().Context(), uuid.MustParse(userID))
	if err != nil {
		if ent.IsNotFound(err) {
			log.Println("unauthorized, begin github oauth")
			return s.redirectGithubOAuth2(ctx, sess)
		}
		return err
	}
	groups, err := user.QueryGroups().All(ctx.Request().Context())
	if err != nil {
		return err
	}

	g := []string{}
	for _, group := range groups {
		g = append(g, group.Name)
	}

	token, ok := ctx.Get(middleware.DefaultCSRFConfig.ContextKey).(string)
	if !ok {
		return errors.New("failed to get csrf token from context")
	}

	return ctx.Render(http.StatusOK, "select-group", map[string]any{
		"User":      user,
		"Groups":    g,
		"CSRFToken": token,
	})
}

func (s *Server) redirectGithubOAuth2(ctx echo.Context, sess *sessions.Session) error {
	state, err := randomString(32)
	if err != nil {
		return err
	}

	sess.Values["github_state_"+state] = map[string]string{
		"return": ctx.Request().URL.String(),
	}

	sess.Options = &sessions.Options{
		Path:     "/",
		HttpOnly: true,
		//TODO: true when production
		Secure: false,
	}
	if err := sess.Save(ctx.Request(), ctx.Response()); err != nil {
		return err
	}

	url := s.oauth2Config.AuthCodeURL(state)

	return ctx.Redirect(http.StatusFound, url)
}

func (s *Server) postOauth2AuthorizeHandle(ctx echo.Context) error {
	var req struct {
		Group string `form:"group"`
	}
	if err := ctx.Bind(&req); err != nil {
		return err
	}

	sess, err := session.Get("session", ctx)
	if err != nil {
		return err
	}

	state, ok := sess.Values["state"].(string)
	if !ok {
		return errors.New("state not found")
	}

	clientID, ok := sess.Values["client_id"].(string)
	if !ok {
		return errors.New("client_id not found'")
	}

	userID := sess.Values["user_id"].(string)
	user, err := s.db.User.Get(ctx.Request().Context(), uuid.MustParse(userID))
	if err != nil {
		return err
	}

	group, err := user.QueryGroups().
		Where(group.Name(req.Group)).
		First(ctx.Request().Context())
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New("invalid group")
		}
		return err
	}

	var c string
	for {
		c, err = randomString(40)
		if err != nil {
			return err
		}
		if exists, err := s.db.Code.Query().
			Where(code.Code(c)).
			Exist(ctx.Request().Context()); err != nil {
			return err
		} else if exists {
			continue
		}

		if _, err := s.db.Code.Create().
			SetGroupID(group.ID).
			SetUserID(user.ID).
			SetCode(c).
			SetExpiresAt(time.Now().Add(time.Minute)).
			SetClientID(clientID).
			Save(ctx.Request().Context()); err != nil {
			return err
		}
		break
	}

	redirectURI, _ := url.Parse("http://localhost:8080/")
	q := redirectURI.Query()
	q.Set("code", c)
	q.Set("state", state)
	redirectURI.RawQuery = q.Encode()
	return ctx.Redirect(http.StatusFound, redirectURI.String())
}

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

func (s *Server) postOauth2TokenHandle(ctx echo.Context) error {
	authzHeader := ctx.Request().Header.Get("Authorization")
	basicUserPassword, ok := strings.CutPrefix(authzHeader, "Basic ")
	if !ok {
		basicUserPassword, ok = strings.CutPrefix(authzHeader, "basic ")
		if !ok {
			return echo.ErrUnauthorized
		}
	}

	if subtle.ConstantTimeCompare([]byte(basicUserPassword), []byte(fmt.Sprintf("%s:%s", s.config.Oauth2.ClientID, s.config.Oauth2.ClientSecret))) == 0 {
		return echo.ErrUnauthorized
	}

	var req struct {
		GrantType   string `form:"grant_type"`
		Code        string `form:"code"`
		RedirectURI string `form:"redirect_uri"`
		ClientID    string `form:"client_id"`
	}
	if err := ctx.Bind(&req); err != nil {
		return err
	}

	if req.GrantType != "authorization_code" {
		return errors.New("invalid grant_type")
	}

	code, err := s.db.Code.Query().Where(code.Code(req.Code)).First(ctx.Request().Context())
	if err != nil {
		return err
	}

	if code.ClientID != req.ClientID {
		return errors.New("invalid client_id")
	}

	if code.RedirectURI != "" && code.RedirectURI == req.RedirectURI {
		return errors.New("invalid redirect_uri")
	}

	if code.ExpiresAt.Before(time.Now()) {
		return errors.New("code expired")
	}

	user, err := code.QueryUser().First(ctx.Request().Context())
	if err != nil {
		return err
	}

	group, err := code.QueryGroup().First(ctx.Request().Context())
	if err != nil {
		return err
	}

	var token *ent.AccessToken
	for {
		t, err := randomString(20)
		if err != nil {
			return err
		}

		if exists, err := s.db.AccessToken.Query().
			Where(accesstoken.Token(t)).
			Exist(ctx.Request().Context()); err != nil {
			return err
		} else if exists {
			continue
		}

		token, err = s.db.AccessToken.Create().
			SetToken(t).
			SetExpiresAt(time.Now().Add(time.Hour)).
			SetUserID(user.ID).
			SetGroupID(group.ID).
			Save(ctx.Request().Context())
		if err != nil {
			return err
		}
		break
	}

	return ctx.JSON(http.StatusOK, map[string]any{
		"access_token":  token.Token,
		"token_type":    "bearer",
		"expires_in":    3600,
		"refresh_token": "",
	})
}

func (s *Server) getUserinfoHandle(ctx echo.Context) error {
	authzHeader := ctx.Request().Header.Get("Authorization")
	token, ok := strings.CutPrefix(authzHeader, "Bearer ")
	if !ok {
		token, ok = strings.CutPrefix(authzHeader, "bearer ")
		if !ok {
			return echo.ErrUnauthorized
		}
	}

	accessToken, err := s.db.AccessToken.Query().
		Where(accesstoken.Token(token)).
		First(ctx.Request().Context())
	if err != nil {
		return err
	}

	user, err := accessToken.QueryUser().First(ctx.Request().Context())
	if err != nil {
		return err
	}

	group, err := accessToken.QueryGroup().First(ctx.Request().Context())
	if err != nil {
		return err
	}

	return ctx.JSON(http.StatusOK, map[string]any{
		"username": user.Name,
		"email":    user.Email,
		"groups":   []string{group.Name},
	})
}
