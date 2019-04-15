package main

import (
	"context"
	"html/template"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/ory/hydra/sdk/go/hydra"
	"github.com/ory/hydra/sdk/go/hydra/swagger"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"
)

// This store will be used to save user authentication
var store = sessions.NewCookieStore([]byte("something-very-secret-keep-it-safe"))

// The session is a unique session identifier
const sessionName = "authentication"

var hydraClient hydra.SDK
var hydraConfig *hydra.Configuration
var oauthConfig *oauth2.Config

// A state for performing the OAuth 2.0 flow. This is usually not part of a consent app, but in order for the demo
// to make sense, it performs the OAuth 2.0 authorize code flow.
var state = "demostatedemostatedemo"

func configureAuth(clientID, clientSecret, publicURL, adminURL string, scopes []string) (*hydra.Configuration, *oauth2.Config) {
	// HYDRA_CLIENT_ID
	// HYDRA_CLIENT_SECRET
	// HYDRA_CLUSTER_URL
	return &hydra.Configuration{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			PublicURL:    publicURL,
			AdminURL:     adminURL,
			Scopes:       scopes,
		}, &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Scopes:       scopes,
			RedirectURL:  "http://localhost:3000/callback",
			Endpoint: oauth2.Endpoint{
				TokenURL: publicURL + "/oauth2/token",
				AuthURL:  publicURL + "/oauth2/auth",
			},
		}
}

func main() {
	var err error

	hydraConfig, oauthConfig = configureAuth("test-client", "test-secret", "http://localhost:4444", "http://localhost:4445", []string{"offline", "openid"})
	if hydraClient, err = hydra.NewSDK(hydraConfig); err != nil {
		log.Fatalf("Unable to connect to the Hydra SDK: %s", err)
	}

	r := mux.NewRouter()
	r.HandleFunc("/", handleHome)
	r.HandleFunc("/consent", handleConsent)
	r.HandleFunc("/login", handleLogin)
	r.HandleFunc("/callback", handleCallback)

	log.Println("Starting server...")
	if err = http.ListenAndServe("localhost:3000", r); err != nil {
		log.Fatalf("Couldn't start server: %s", err)
	}
}

// the main page we want our users to hit
func handleHome(w http.ResponseWriter, _ *http.Request) {
	var authURL = oauthConfig.AuthCodeURL(state) + "&nonce=" + state
	renderTemplate(w, "home.html", authURL)
}

// if the user is not authenticated, hydra will redirect here
func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		if err := r.ParseForm(); err != nil {
			http.Error(w, errors.Wrap(err, "Could not parse form").Error(), http.StatusBadRequest)
			return
		}

		// check the user's credentials
		if r.Form.Get("username") != "buzz" || r.Form.Get("password") != "lightyear" {
			http.Error(w, "Provided credentials are wrong, try buzz:lightyear", http.StatusBadRequest)
			return
		}

		// create a session with the user id
		session, _ := store.Get(r, sessionName)
		session.Values["user"] = "buzz-lightyear"

		// store the session in the cookie
		if err := store.Save(r, w, session); err != nil {
			http.Error(w, errors.Wrap(err, "Could not persist cookie").Error(), http.StatusBadRequest)
			return
		}

		challenge := r.URL.Query().Get("challenge")
		_, _, err := hydraClient.GetLoginRequest(challenge)
		if err != nil {
			http.Error(w, errors.Wrap(err, "Could not get login request").Error(), http.StatusBadRequest)
			return
		}

		completedRequest, _, err := hydraClient.AcceptLoginRequest(challenge, swagger.AcceptLoginRequest{
			Subject:     "buzz",
			Remember:    true,
			RememberFor: 3600,
		})

		// redirect the user back to hydra
		http.Redirect(w, r, completedRequest.RedirectTo, http.StatusFound)
		return
	}

	challenge := r.URL.Query().Get("login_challenge")
	renderTemplate(w, "login.html", challenge)
}

// authenticated user needs to set scope
func handleConsent(w http.ResponseWriter, r *http.Request) {
	challenge := r.URL.Query().Get("consent_challenge")
	if challenge == "" {
		if challenge = r.URL.Query().Get("consent"); challenge == "" {
			http.Error(w, errors.New("Consent endpoint was called without a consent request id").Error(), http.StatusBadRequest)
			return
		}
	}

	// fetch consent information
	consentRequest, response, err := hydraClient.GetConsentRequest(challenge)
	if err != nil {
		http.Error(w, errors.Wrap(err, "The consent request endpoint did not respond").Error(), http.StatusBadRequest)
		return
	} else if response.StatusCode != http.StatusOK {
		http.Error(w, errors.Wrapf(err, "Consent request endpoint gave status code %d but expected %d", response.StatusCode, http.StatusOK).Error(), http.StatusBadRequest)
		return
	}

	if r.Method == "POST" {
		// let's check which scopes the user granted
		if err := r.ParseForm(); err != nil {
			http.Error(w, errors.Wrap(err, "Could not parse form").Error(), http.StatusBadRequest)
			return
		}

		var grantedScopes = []string{}
		for key := range r.PostForm {
			// add each scope to the list of granted scopes
			grantedScopes = append(grantedScopes, key)
		}

		acceptRequest, _, err := hydraClient.AcceptConsentRequest(challenge, swagger.AcceptConsentRequest{
			// We can grant all scopes that have been requested - hydra already checked for us that no additional scopes
			// are requested accidentally.
			GrantScope: grantedScopes,

			// ORY Hydra checks if requested audiences are allowed by the client, so we can simply echo this.
			GrantAccessTokenAudience: consentRequest.RequestedAccessTokenAudience,

			// // The session allows us to set session data for id and access tokens
			// Session: map[string]interface{}{
			// 	// This data will be available when introspecting the token. Try to avoid sensitive information here,
			// 	// unless you limit who can introspect tokens.
			// 	// access_token: { foo: 'bar' },

			// 	// This data will be available in the ID token.
			// 	// id_token: { baz: 'bar' },
			// },

			Remember: true,

			// When this "remember" session expires, in seconds. Set this to 0 so it will never expire.
			RememberFor: 3600,
		})
		if err != nil {
			http.Error(w, errors.Wrap(err, "The accept consent request endpoint encountered a network error").Error(), http.StatusInternalServerError)
			return
		}

		// redirect the user back to hydra
		http.Redirect(w, r, acceptRequest.RedirectTo, http.StatusFound)
		return
	}

	renderTemplate(w, "consent.html", struct {
		RequestedScopes []string
		Challenge       string
	}{RequestedScopes: oauthConfig.Scopes, Challenge: challenge})
}

// Once the user has given their consent, we will hit this endpoint. Again,
// this is not something that would be included in a traditional consent app,
// but we added it so you can see the data once the consent flow is done.
func handleCallback(w http.ResponseWriter, r *http.Request) {
	// TODO: check the state query parameter

	// exchange the access code for an access (and optionally) a refresh token
	token, err := oauthConfig.Exchange(context.Background(), r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, errors.Wrap(err, "Could not exchange token").Error(), http.StatusBadRequest)
		return
	}

	renderTemplate(w, "callback.html", struct {
		*oauth2.Token
		IDToken interface{}
	}{
		Token:   token,
		IDToken: token.Extra("id_token"),
	})
}

// renderTemplate is a convenience helper for rendering templates
func renderTemplate(w http.ResponseWriter, id string, d interface{}) bool {
	if t, err := template.New(id).ParseFiles("./templates/" + id); err != nil {
		http.Error(w, errors.Wrap(err, "Could not render template").Error(), http.StatusInternalServerError)
		return false
	} else if err := t.Execute(w, d); err != nil {
		http.Error(w, errors.Wrap(err, "Could not render template").Error(), http.StatusInternalServerError)
		return false
	}
	return true
}
