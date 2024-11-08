package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
	"golang.org/x/oauth2"
)

func main() {
	conf := oauth2.Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		Endpoint: oauth2.Endpoint{
			AuthURL:  "http://localhost:8080/oauth2/authorize",
			TokenURL: "http://localhost:8080/oauth2/token",
		},
		RedirectURL: "http://localhost:8081/oauth2/callback",
	}

	state := uuid.Must(uuid.NewRandom())
	url := conf.AuthCodeURL(state.String())
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

		token, err := conf.Exchange(r.Context(), code, oauth2.SetAuthURLParam("client_id", conf.ClientID))
		if err != nil {
			log.Fatal(err)
		}

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
		Addr:    ":8081",
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
