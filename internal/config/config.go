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

type Github struct {
	ClientID     string `yaml:"clientID"`
	ClientSecret string `yaml:"clientSecret"`
	RedirectURL  string `yaml:"redirectURL"`
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
		Endpoint: github.Endpoint,
	}
}

type Database struct {
	Type       string `yaml:"type"`
	DataSource string `yaml:"dataSource"`
}

func (d *Database) Open() (*ent.Client, error) {
	return ent.Open(d.Type, d.DataSource)
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
