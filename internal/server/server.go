package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/gob"
	"errors"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/ophum/github-teams-oauth2/ent"
	"github.com/ophum/github-teams-oauth2/ent/accesstoken"
	"github.com/ophum/github-teams-oauth2/ent/code"
	"github.com/ophum/github-teams-oauth2/ent/group"
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

	var req BeginAuthorizeRequest
	if err := ctx.Bind(&req); err != nil {
		return err
	}

	if req.ResponseType != ResponseTypeCode {
		return errors.New("invalid response_type")
	}

	if req.ClientID != s.config.Oauth2.ClientID {
		return errors.New("invalid client_id'")
	}

	scopes := excludeInvalidScopes(strings.Split(req.Scope, " "), []string{
		"openid",
	})

	sess.Values["client_id"] = req.ClientID
	sess.Values["state"] = req.State
	sess.Values["redirect_uri"] = req.RedirectURI
	sess.Values["scopes"] = scopes
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

	return render(ctx, http.StatusOK, "select-group", map[string]any{
		"User":   user,
		"Groups": groups,
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
	var req PostAuthorizeRequest
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

	redirectURI, ok := sess.Values["redirect_uri"].(string)
	if !ok {
		return errors.New("invalid redirect_uri")
	}

	scopes, ok := sess.Values["scopes"].([]string)
	if !ok {
		return errors.New("invalid scopes")
	}

	userID := sess.Values["user_id"].(string)
	user, err := s.db.User.Get(ctx.Request().Context(), uuid.MustParse(userID))
	if err != nil {
		return err
	}

	if exists, err := user.QueryGroups().
		Where(group.IDIn(req.GroupIDs...)).
		Exist(ctx.Request().Context()); err != nil {
		return err
	} else if !exists {
		return errors.New("invalid group")
	}

	code, err := createCode(ctx.Request().Context(), s.db,
		user.ID,
		req.GroupIDs,
		clientID,
		strings.Join(scopes, " "),
	)
	if err != nil {
		return err
	}

	r, _ := url.Parse(redirectURI)
	q := r.Query()
	q.Set("code", code.Code)
	q.Set("state", state)
	r.RawQuery = q.Encode()
	return ctx.Redirect(http.StatusFound, r.String())
}

func (s *Server) postOauth2TokenHandle(ctx echo.Context) error {
	username, password, err := getBasicUserPassword(ctx.Request().Header)
	if err != nil {
		log.Println(err)
		return echo.ErrUnauthorized
	}

	if subtle.ConstantTimeCompare([]byte(username), []byte(s.config.Oauth2.ClientID)) == 0 {
		return echo.ErrUnauthorized
	}
	if subtle.ConstantTimeCompare([]byte(password), []byte(s.config.Oauth2.ClientSecret)) == 0 {
		return echo.ErrUnauthorized
	}

	var req TokenRequest
	if err := ctx.Bind(&req); err != nil {
		return err
	}

	if req.GrantType != GrantTypeAuthorizationCode {
		return errors.New("invalid grant_type")
	}

	code, err := s.db.Code.Query().Where(code.Code(req.Code)).First(ctx.Request().Context())
	if err != nil {
		return err
	}

	// ↑でBasic認証(confidential)を行っているのでclient_idを見る必要がない
	// 逆にBasic認証を不要とする場合(public)は見る必要がある
	//if code.ClientID != req.ClientID {
	//	return errors.New("invalid client_id")
	//}

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

	groups, err := code.QueryGroups().All(ctx.Request().Context())
	if err != nil {
		return err
	}

	token, err := createAccessToken(ctx.Request().Context(), s.db,
		user.ID, slicesMap(groups, func(v *ent.Group) uuid.UUID {
			return v.ID
		}))
	if err != nil {
		return err
	}

	scopes := strings.Split(code.Scope, " ")

	ret := map[string]any{
		"access_token":  token.Token,
		"token_type":    "bearer",
		"expires_in":    3600,
		"refresh_token": "",
	}

	if slices.Contains(scopes, "openid") {
		hash := sha256.Sum256([]byte(token.Token))
		atHash := base64.StdEncoding.EncodeToString(hash[:16])
		idToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"iss":      "http://localhost:8080",
			"at_hash":  atHash,
			"sub":      user.ID,
			"aud":      []string{},
			"exp":      time.Now().Add(time.Hour).Unix(),
			"iat":      time.Now().Unix(),
			"username": user.Name,
			"email":    user.Email,
			"groups": slicesMap(groups, func(v *ent.Group) string {
				return v.Name
			}),
		})
		ret["id_token"], err = idToken.SignedString([]byte("secret"))
		if err != nil {
			return err
		}
	}
	return ctx.JSON(http.StatusOK, ret)
}

func (s *Server) getUserinfoHandle(ctx echo.Context) error {
	token, err := getBearerToken(ctx.Request().Header)
	if err != nil {
		return echo.ErrUnauthorized
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

	groups, err := accessToken.QueryGroups().All(ctx.Request().Context())
	if err != nil {
		return err
	}

	return ctx.JSON(http.StatusOK, map[string]any{
		"id":       user.ID.String(),
		"username": user.Name,
		"email":    user.Email,
		"groups": slicesMap(groups, func(v *ent.Group) string {
			return v.Name
		}),
	})
}
