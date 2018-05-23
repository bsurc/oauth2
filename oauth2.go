// Copyright (c) 2017, Boise State University All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package oauth2

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"

	"github.com/bsurc/sessions"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const (
	noMatch    = `x^`
	emailScope = "https://www.googleapis.com/auth/userinfo.email"
	// BSUEmail is a valid regexp for any BSU address
	BSUEmail = `^.+@(u\.)?boisestate.edu$`
)

type oauthUser struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Domain        string `json:"hd"`
}

// Client supplies the ability to authenticate via OAuth2 on Google, but more
// specifically for BSU people through Google.  Access for specific users can
// be added, or using a regular expression.
type Client struct {
	sm          *sessions.Manager
	mu          sync.Mutex
	m           map[string]*oauth2.Token
	match       *regexp.Regexp
	whitelist   map[string]struct{}
	oauthState  string
	oauthConfig *oauth2.Config
	httpClients map[string]*http.Client
	// When checking the whitelist governed by Grant/Revoke, check using
	// ToLower()
	CI bool
}

// AuthHandler
func (c *Client) AuthHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Check the state that was sent with the request
	if r.FormValue("state") != c.oauthState {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	tok, err := c.oauthConfig.Exchange(context.TODO(), r.FormValue("code"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	client := c.oauthConfig.Client(oauth2.NoContext, tok)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer resp.Body.Close()

	var u oauthUser
	err = json.NewDecoder(resp.Body).Decode(&u)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if c.CI {
		u.Email = strings.ToLower(u.Email)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.whitelist[u.Email]
	if !c.match.MatchString(u.Email) && !ok {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	c.sm.Set(w, r, "sub", u.Sub)
	c.sm.Set(w, r, "email", u.Email)
	c.m[u.Email] = tok
	c.httpClients[u.Email] = client

	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

// ShimHandler
func (c *Client) ShimHandler(h http.Handler) http.Handler {
	f := func(w http.ResponseWriter, r *http.Request) {
		email, err := c.sm.Get(r, "email")
		if err != nil {
			log.Print(err)
			http.Redirect(w, r, c.oauthConfig.AuthCodeURL(c.oauthState, oauth2.AccessTypeOffline), http.StatusTemporaryRedirect)
			return
		}
		c.mu.Lock()
		tok, ok := c.m[email]
		c.mu.Unlock()
		if err != nil || !ok || tok == nil || !tok.Valid() {
			log.Print(err)
			http.Redirect(w, r, c.oauthConfig.AuthCodeURL(c.oauthState, oauth2.AccessTypeOffline), http.StatusTemporaryRedirect)
			return
		}
		h.ServeHTTP(w, r)
	}
	return http.HandlerFunc(f)
}

// Config holds the information necessary to create a new client
type Config struct {
	// Token is the google OAuth2 client id
	Token string
	// Secret is the google OAuth2 client secret
	Secret string
	// RedirectURL is the URL to redirect to after authentication
	RedirectURL string
	// Regexp is the regular expression string that emails must match for access
	Regexp string
	// Scopes are the OAuth2 scopes.  The email scope is always set.
	Scopes []string
	// Cookie name is the name of the cookie that stores session information
	CookieName string
}

// NewClient returns a client that has two helper functions, one is an
// AuthHandler with needs to be installed at the same address as redirect, the
// other is a Shim that checks for valid credentials and rejects the
// unauthorized users.  If the regex is set, the email of the user must match
// it.  Explicit Google or BSU emails can be set using Grant/Revoke.
//
// TODO(kyle): show Auth and Shim examples
func NewClient(c Config) (*Client, error) {
	if c.CookieName == "" {
		return nil, fmt.Errorf("must supply a cookie name")
	}
	if c.Regexp == "" {
		c.Regexp = noMatch
	}

	hasEmailScope := false

	for _, s := range c.Scopes {
		if s == emailScope {
			hasEmailScope = true
		}
	}
	if !hasEmailScope {
		c.Scopes = append(c.Scopes, "https://www.googleapis.com/auth/userinfo.email")
	}

	match, err := regexp.Compile(c.Regexp)
	if err != nil {
		return nil, err
	}

	oc := &Client{
		oauthConfig: &oauth2.Config{
			ClientID:     c.Token,
			ClientSecret: c.Secret,
			RedirectURL:  c.RedirectURL,
			Scopes:       c.Scopes,
			Endpoint:     google.Endpoint,
		},
		sm:          sessions.NewManager(c.CookieName),
		m:           map[string]*oauth2.Token{},
		httpClients: map[string]*http.Client{},
		match:       match,
	}

	x := make([]byte, 32)
	rand.Read(x)
	oc.oauthState = fmt.Sprintf("%x", x)
	oc.whitelist = map[string]struct{}{}
	return oc, nil
}

// Grant allows the user with the supplied email access
func (c *Client) Grant(email string) {
	if c.CI {
		email = strings.ToLower(email)
	}
	c.mu.Lock()
	c.whitelist[email] = struct{}{}
	c.mu.Unlock()
}

// Revoke removes the user with the supplied email from the whitelist
func (c *Client) Revoke(email string) {
	c.mu.Lock()
	if _, ok := c.whitelist[email]; ok {
		delete(c.whitelist, email)
	}
	c.mu.Unlock()
}

// Email returns the email that is associated with the session passed in.
//
// We'd like to expose who is has a valid session, but I don't like this.  Fix
// it.
func (c *Client) Email(r *http.Request) string {
	email, _ := c.sm.Get(r, "email")
	return email
}

func (c *Client) HTTPClient(r *http.Request) *http.Client {
	email, _ := c.sm.Get(r, "email")
	c.mu.Lock()
	client := c.httpClients[email]
	c.mu.Unlock()
	return client
}
