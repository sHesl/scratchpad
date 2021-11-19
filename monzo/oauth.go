package monzo

import (
	"context"
	"net/http"

	"github.com/pkg/browser"
	"golang.org/x/oauth2"
)

// initiates the oauth flow for the Monzo API
func oauthFlow(conf *oauth2.Config) (*oauth2.Token, error) {
	respCh := make(chan string, 1)
	srv := http.Server{Addr: ":8080"}
	srv.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		respCh <- r.URL.Query().Get("code")
		w.WriteHeader(200)
	})

	go srv.ListenAndServe()
	defer srv.Shutdown(context.Background())

	url := conf.AuthCodeURL("xxx")
	if err := browser.OpenURL(url); err != nil {
		return nil, err
	}

	return conf.Exchange(context.Background(), <-respCh)
}

func oauthConfig(clientID, clientSecret, localhostRedirectURL string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint: oauth2.Endpoint{
			TokenURL: "https://api.monzo.com/oauth2/token",
			AuthURL:  "https://auth.monzo.com",
		},
		RedirectURL: localhostRedirectURL,
	}
}
