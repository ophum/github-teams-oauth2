/*
Copyright © 2024 Takahiro INAGAKI <inagaki0106@gmail.com>
*/
package cmd

import (
	"context"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"slices"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/ophum/github-teams-oauth2/ent"
	"github.com/ophum/github-teams-oauth2/ent/code"
	"github.com/ophum/github-teams-oauth2/ent/group"
	"github.com/ophum/github-teams-oauth2/ent/user"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/oauth2"

	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"
)

// serverCmd represents the server command
var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if err := viper.Unmarshal(&conf); err != nil {
			return err
		}
		db, err := conf.Database.Open()
		if err != nil {
			return err
		}
		defer db.Close()

		if err := db.Schema.Create(context.Background()); err != nil {
			return err
		}
		return nil

	},
	RunE: func(cmd *cobra.Command, args []string) error {

		return serverRun()
	},
}

func init() {
	rootCmd.AddCommand(serverCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// serverCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// serverCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	gob.Register(map[string]string{})
}

type Template struct {
	templates *template.Template
}

func (t *Template) Render(w io.Writer, name string, data any, c echo.Context) error {
	return t.templates.ExecuteTemplate(w, name, data)
}
func serverRun() error {
	t := &Template{
		templates: template.Must(template.ParseGlob("views/*.html")),
	}

	e := echo.New()
	e.Renderer = t
	e.Use(middleware.Logger())

	withSession := e.Group("", session.Middleware(sessions.NewCookieStore([]byte("secret"))))
	withSession.GET("/oauth2/authorize", getOauth2AuthorizeHandle)
	withSession.POST("/oauth2/authorize", postOauth2AuthorizeHandle)
	withSession.GET("/oauth2/github/callback", getOauth2GithubCallbackHandle)

	e.Logger.Fatal(e.Start(":8080"))
	return nil

}

func getOauth2AuthorizeHandle(ctx echo.Context) error {
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

	// TODO: 設定ファイルorDBを参照したい
	if req.ClientID != "test-client-id" {
		return errors.New("invalid client_id'")
	}
	sess.Values["state"] = req.State

	userID, ok := sess.Values["user_id"].(string)
	if !ok {
		log.Println("unauthorized, begin github oatuth")
		return redirectGithubOAuth2(ctx, sess)
	}
	db, err := conf.Database.Open()
	if err != nil {
		return err
	}
	defer db.Close()
	user, err := db.User.Get(ctx.Request().Context(), uuid.MustParse(userID))
	if err != nil {
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
	return ctx.Render(http.StatusOK, "select-group", map[string]any{
		"User":   user,
		"Groups": g,
	})
}

func redirectGithubOAuth2(ctx echo.Context, sess *sessions.Session) error {
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

	url := conf.Github.OAuth2Config().AuthCodeURL(state)

	return ctx.Redirect(http.StatusFound, url)
}

func postOauth2AuthorizeHandle(ctx echo.Context) error {
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

	db, err := conf.Database.Open()
	if err != nil {
		return err
	}
	defer db.Close()

	userID := sess.Values["user_id"].(string)
	user, err := db.User.Get(ctx.Request().Context(), uuid.MustParse(userID))
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
		if exists, err := db.Code.Query().
			Where(code.Code(c)).
			Exist(ctx.Request().Context()); err != nil {
			return err
		} else if exists {
			continue
		}

		if _, err := db.Code.Create().
			SetGroupID(group.ID).
			SetUserID(user.ID).
			SetCode(c).
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

func getOauth2GithubCallbackHandle(ctx echo.Context) error {
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

	token, err := conf.Github.OAuth2Config().Exchange(ctx.Request().Context(), callbackParams.Code)
	if err != nil {
		return err
	}

	email, err := getGithubUserEmail(ctx.Request().Context(), token)
	if err != nil {
		return err
	}

	orgTeams, err := getGithubOrgTeams(ctx.Request().Context(), token)
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

	db, err := conf.Database.Open()
	if err != nil {
		return err
	}
	defer db.Close()

	user, err := db.User.Query().Where(user.Name(email)).First(ctx.Request().Context())
	if err != nil {
		if !ent.IsNotFound(err) {
			return err
		}

		user, err = db.User.Create().
			SetName(email).
			Save(ctx.Request().Context())
		if err != nil {
			return err
		}
	}

	builders := []*ent.GroupCreate{}
	for _, group := range ret {
		builders = append(builders, db.Group.Create().SetName(group))
	}
	if err := db.Group.CreateBulk(builders...).
		OnConflictColumns(group.FieldName).
		DoNothing().
		UpdateNewValues().
		Exec(ctx.Request().Context()); err != nil {
		return err
	}

	dgroups, err := db.Group.Query().Where(group.NameIn(ret...)).All(ctx.Request().Context())
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

func getGithubUserEmail(ctx context.Context, token *oauth2.Token) (string, error) {
	client := conf.Github.OAuth2Config().Client(ctx, token)

	resp, err := client.Get("https://api.github.com/user/emails")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var res []*struct {
		Email   string `json:"email"`
		Primary bool   `json:"primary"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return "", err
	}

	for _, email := range res {
		if email.Primary {
			return email.Email, nil
		}
	}
	return "", errors.New("not found")
}

func getGithubOrgTeams(ctx context.Context, token *oauth2.Token) (map[string][]string, error) {
	client := conf.Github.OAuth2Config().Client(ctx, token)
	resp, err := client.Get("https://api.github.com/user/teams")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var res []*struct {
		Slug         string
		Organization struct {
			Login string
		}
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, err
	}

	orgTeams := map[string][]string{}
	for _, team := range res {
		orgTeams[team.Slug] = append(orgTeams[team.Slug], team.Organization.Login)
	}
	return orgTeams, nil
}
