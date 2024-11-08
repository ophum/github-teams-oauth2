package server

import (
	"context"
	"encoding/json"
	"errors"

	"golang.org/x/oauth2"
)

func (s *Server) getGithubUser(ctx context.Context, token *oauth2.Token) (string, error) {
	client := s.oauth2Config.Client(ctx, token)

	resp, err := client.Get(s.config.Github.APIBaseURL + "/user")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var res struct {
		Login string `json:"login"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return "", err
	}

	return res.Login, nil
}

func (s *Server) getGithubUserEmail(ctx context.Context, token *oauth2.Token) (string, error) {
	client := s.oauth2Config.Client(ctx, token)

	resp, err := client.Get(s.config.Github.APIBaseURL + "/user/emails")
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

func (s *Server) getGithubOrgTeams(ctx context.Context, token *oauth2.Token) (map[string][]string, error) {
	client := s.oauth2Config.Client(ctx, token)
	resp, err := client.Get(s.config.Github.APIBaseURL + "/user/teams")
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
		orgTeams[team.Organization.Login] = append(orgTeams[team.Organization.Login], team.Slug)
	}
	return orgTeams, nil
}
