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
	gob.Register(BeginAuthorizeRequest{})
	gob.Register(map[string]BeginAuthorizeRequest{})
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
	withSession.GET("/sign-in", s.getSignIn)
	withSession.POST("/sign-in", s.postSignIn)
	withSession.POST("/sign-out", s.postSignOut)

	e.POST("/oauth2/token", s.postOauth2TokenHandle)
	e.GET("/userinfo", s.getUserinfoHandle)

	e.Logger.Fatal(e.Start(":8080"))
	return nil
}

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

func (s *Server) getOauth2AuthorizeHandle(ctx echo.Context) error {
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

	user, err := getAuthUser(ctx, s.db)
	if err != nil {
		if errors.Is(err, echo.ErrUnauthorized) {
			log.Println("unauthorized, redirect sign-in page")
			return s.redirectSignInPage(ctx)
		}
		return err
	}

	scopes := excludeInvalidScopes(strings.Split(req.Scope, " "), []string{
		"openid",
		"groups",
	})

	isGroups := slices.Contains(scopes, "groups")

	var groups []*ent.Group
	if isGroups {
		groups, err = user.QueryGroups().All(ctx.Request().Context())
		if err != nil {
			return err
		}
	}

	return render(ctx, http.StatusOK, "select-group", map[string]any{
		"User":                  user,
		"Groups":                groups,
		"IsGroups":              isGroups,
		"BeginAuthorizeRequest": req,
	})
}

func (s *Server) redirectSignInPage(ctx echo.Context) error {
	q := url.Values{}
	q.Set("redirect_uri", ctx.Request().RequestURI)

	signInURL, _ := url.Parse("/sign-in")
	signInURL.RawQuery = q.Encode()

	return ctx.Redirect(http.StatusFound, signInURL.String())
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

	userID := sess.Values["user_id"].(string)
	user, err := s.db.User.Get(ctx.Request().Context(), uuid.MustParse(userID))
	if err != nil {
		return err
	}

	scopes := excludeInvalidScopes(strings.Split(req.Scope, " "), []string{
		"openid",
		"groups",
	})

	var groupIDs []uuid.UUID
	if slices.Contains(scopes, "groups") {
		groupIDs = req.GroupIDs

		if exists, err := user.QueryGroups().
			Where(group.IDIn(req.GroupIDs...)).
			Exist(ctx.Request().Context()); err != nil {
			return err
		} else if !exists {
			return errors.New("invalid group")
		}
	}

	_, originalCode, err := createCode(ctx.Request().Context(), s.db,
		user.ID,
		groupIDs,
		req.ClientID,
		strings.Join(scopes, " "),
	)
	if err != nil {
		return err
	}

	r, _ := url.Parse(req.RedirectURI)
	q := r.Query()
	q.Set("code", originalCode)
	q.Set("state", req.State)
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

	hashedCode := sha512String(req.Code)
	code, err := s.db.Code.Query().Where(code.Code(hashedCode)).First(ctx.Request().Context())
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

	_, token, err := createAccessToken(ctx.Request().Context(), s.db,
		user.ID, slicesMap(groups, func(v *ent.Group) uuid.UUID {
			return v.ID
		}))
	if err != nil {
		return err
	}

	scopes := strings.Split(code.Scope, " ")

	ret := map[string]any{
		"access_token":  token,
		"token_type":    "bearer",
		"expires_in":    3600,
		"refresh_token": "",
	}

	if slices.Contains(scopes, "openid") {
		hash := sha256.Sum256([]byte(token))
		atHash := base64.StdEncoding.EncodeToString(hash[:16])
		claims := jwt.MapClaims{
			"iss":      "http://localhost:8080",
			"at_hash":  atHash,
			"sub":      user.ID,
			"aud":      []string{},
			"exp":      time.Now().Add(time.Hour).Unix(),
			"iat":      time.Now().Unix(),
			"username": user.Name,
			"email":    user.Email,
		}
		if slices.Contains(scopes, "groups") {
			claims["groups"] = slicesMap(groups, func(v *ent.Group) string {
				return v.Name
			})
		}
		idToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

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
