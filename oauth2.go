// Copyright (c) 2017, Boise State University All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package oauth2

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sync"

	"github.com/bsurc/sessions"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const (
	cookieName = "bsuOAuthKey"
	bsuEmail   = `^.+@(u\.)?boisestate.edu$`
)

type oauthUser struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Domain        string `json:"hd"`
}

func (c *Client) AuthHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	tok, err := c.oauthConfig.Exchange(oauth2.NoContext, r.FormValue("code"))
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
	if !c.match.MatchString(u.Email) {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	c.sm.Set(w, r, "sub", u.Sub)
	c.sm.Set(w, r, "email", u.Email)
	c.mu.Lock()
	c.m[u.Email] = tok
	c.mu.Unlock()
	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

func (c *Client) ShimHandler(h http.Handler) http.Handler {
	f := func(w http.ResponseWriter, r *http.Request) {
		var email string
		var err error
		email, err = c.sm.Get(r, "email")
		c.mu.Lock()
		tok := c.m[email]
		c.mu.Unlock()
		if err != nil || tok == nil || !tok.Valid() {
			http.Redirect(w, r, c.oauthConfig.AuthCodeURL(c.oauthState), http.StatusTemporaryRedirect)
			return
		}
		h.ServeHTTP(w, r)
	}
	return http.HandlerFunc(f)
}

func NewClient(token, secret, redirect string) *Client {
	c := &Client{
		oauthConfig: &oauth2.Config{
			ClientID:     token,
			ClientSecret: secret,
			RedirectURL:  redirect,
			Scopes: []string{
				"https://www.googleapis.com/auth/userinfo.email",
			},
			Endpoint: google.Endpoint,
		},
		sm:    sessions.NewManager(cookieName),
		m:     map[string]*oauth2.Token{},
		match: regexp.MustCompile(bsuEmail),
	}

	x := make([]byte, 32)
	rand.Read(x)
	c.oauthState = fmt.Sprintf("%x", x)
	return c
}

type Client struct {
	sm          *sessions.Manager
	mu          sync.Mutex
	m           map[string]*oauth2.Token
	match       *regexp.Regexp
	oauthState  string
	oauthConfig *oauth2.Config
}
