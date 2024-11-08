package config

import (
	"net"
	"strconv"

	_ "github.com/lib/pq"
	"github.com/ophum/github-teams-oauth2/ent"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"gopkg.in/boj/redistore.v1"
)

type Config struct {
	Github   Github   `yaml:"github"`
	Database Database `yaml:"database"`
	Session  Session  `yaml:"session"`
}

func (c *Config) SetDefault() {
	c.Github.setDefault()
}

type Github struct {
	ClientID      string `yaml:"clientID"`
	ClientSecret  string `yaml:"clientSecret"`
	RedirectURL   string `yaml:"redirectURL"`
	APIBaseURL    string `yaml:"apiBaseURL"`
	AuthURL       string `yaml:"authURL"`
	TokenURL      string `yaml:"tokenURL"`
	DeviceAuthURL string `yaml:"deviceAuthURL"`
}

func (g *Github) setDefault() {
	if g.APIBaseURL == "" {
		g.APIBaseURL = "https://api.github.com"
	}
	if g.AuthURL == "" {
		g.AuthURL = github.Endpoint.AuthURL
	}
	if g.TokenURL == "" {
		g.TokenURL = github.Endpoint.TokenURL
	}
	if g.DeviceAuthURL == "" {
		g.DeviceAuthURL = github.Endpoint.DeviceAuthURL
	}
}

func (g Github) OAuth2Config() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     g.ClientID,
		ClientSecret: g.ClientSecret,
		RedirectURL:  g.RedirectURL,
		Scopes: []string{
			"user:email",
			"read:org",
		},
		Endpoint: oauth2.Endpoint{
			AuthURL:       g.AuthURL,
			TokenURL:      g.TokenURL,
			DeviceAuthURL: g.DeviceAuthURL,
		},
	}
}

type Database struct {
	Type       string `yaml:"type"`
	DataSource string `yaml:"dataSource"`
	IsDebug    bool   `yaml:"isDebug"`
}

func (d *Database) Open() (*ent.Client, error) {
	db, err := ent.Open(d.Type, d.DataSource)
	if err != nil {
		return nil, err
	}
	if d.IsDebug {
		db = db.Debug()
	}
	return db, nil
}

type Session struct {
	Redis SessionRedis `yaml:"redis"`
}

type SessionRedis struct {
	Address string `yaml:"address"`
	Port    int    `yaml:"port"`
	Secret  string `yaml:"secret"`
}

func (sr *SessionRedis) Open() (*redistore.RediStore, error) {
	return redistore.NewRediStore(10, "tcp",
		net.JoinHostPort(sr.Address, strconv.Itoa(sr.Port)),
		"",
		[]byte(sr.Secret))
}
