package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"
	"golang.org/x/oauth2"
)

func main() {
	port := "8081"
	if len(os.Args) == 2 {
		port = os.Args[1]
	}

	var isPublic bool
	flag.BoolVar(&isPublic, "public", false, "public client")
	flag.Parse()

	conf := oauth2.Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		Endpoint: oauth2.Endpoint{
			AuthURL:  "http://localhost:8080/oauth2/authorize",
			TokenURL: "http://localhost:8080/oauth2/token",
		},
		RedirectURL: "http://localhost:" + port + "/oauth2/callback",
		Scopes: []string{
			"openid",
			"groups",
		},
	}

	if isPublic {
		conf.ClientSecret = ""
	}

	verifier := oauth2.GenerateVerifier()
	log.Println("verifier:", verifier)

	state := uuid.Must(uuid.NewRandom())

	opts := []oauth2.AuthCodeOption{}
	if isPublic {
		opts = append(opts, oauth2.S256ChallengeOption(verifier))
	}
	url := conf.AuthCodeURL(state.String(), opts...)
	fmt.Println("url:", url)

	doneCh := make(chan struct{})
	http.HandleFunc("/oauth2/callback", func(w http.ResponseWriter, r *http.Request) {
		code := r.FormValue("code")
		s := r.FormValue("state")

		fmt.Println("code:", code)
		fmt.Println("state:", s)

		if state.String() != s {
			log.Fatal("mismatch state")
		}

		opts := []oauth2.AuthCodeOption{}
		if isPublic {
			opts = append(opts, []oauth2.AuthCodeOption{
				oauth2.SetAuthURLParam("client_id", conf.ClientID),
				oauth2.VerifierOption(verifier),
			}...)
		}
		token, err := conf.Exchange(r.Context(),
			code,
			opts...,
		)
		if err != nil {
			log.Fatal(err)
		}

		idToken := token.Extra("id_token")
		fmt.Println("id_token:", idToken)
		c := conf.Client(r.Context(), token)
		resp, err := c.Get("http://localhost:8080/userinfo")
		if err != nil {
			log.Fatal(err)
		}
		defer resp.Body.Close()

		res, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(string(res))

		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("authorized")); err != nil {
			log.Fatal(err)
		}
		doneCh <- struct{}{}
	})

	server := http.Server{
		Addr:    ":" + port,
		Handler: http.DefaultServeMux,
	}
	go func() {
		if err := server.ListenAndServe(); err != nil {
			log.Fatal(err)
		}
	}()
	<-doneCh

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Fatal(err)
	}
}
