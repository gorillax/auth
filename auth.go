package auth

import (
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"net/http"
	"path"
	"regexp"
)

func NewBasicAuthManager() *AuthManager {
	return &AuthManager{
		mux.NewRouter(),
		sessions.NewCookieStore([]byte("unsecured")),
		"sessionName",
		[]string{},
		nil,
		nil,
		nil,
	}
}

func NewAuthManager(router *mux.Router, store sessions.Store, sessionName string, securedURLs []string, passwordEncoder PasswordEncoder, userDetailsService UserDetailsService, accessDeniedHanlder http.Handler) *AuthManager {
	return &AuthManager{
		router,
		store,
		sessionName,
		securedURLs,
		passwordEncoder,
		userDetailsService,
		accessDeniedHanlder,
	}
}

type AuthManager struct {
	*mux.Router
	Store               sessions.Store
	sessionName         string
	SecuredURLs         []string
	PasswordEncoder     PasswordEncoder
	UserDetailsService  UserDetailsService
	AccessDeniedHanlder http.Handler
}

const (
	AUTHENTICATED_PRINCIPAL = "AUTH_PRINCIPAL"
)

type AuthenticatedPrincipal string

func (a *AuthManager) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	session, _ := a.Store.Get(req, a.sessionName)
	authPrincipal := session.Values[AUTHENTICATED_PRINCIPAL]
	if a.isAuthRequired(req) && authPrincipal == nil {
		if a.AccessDeniedHanlder != nil {
			a.AccessDeniedHanlder.ServeHTTP(w, req)
			return
		}
		http.Redirect(w, req, "/", http.StatusFound)
	}
	a.Router.ServeHTTP(w, req)
}

func (a *AuthManager) AuthenticateUser(w http.ResponseWriter, req *http.Request, username, rawPassword string) bool {
	userDetails := a.UserDetailsService.LoadUserByUsername(username)
	if userDetails != nil {
		return false
	}
	if !a.PasswordEncoder.Matches(rawPassword, userDetails.GetPassword()) {
		return false
	}
	session, _ := a.Store.Get(req, a.sessionName)
	session.Values[AUTHENTICATED_PRINCIPAL] = userDetails.GetUsername()
	session.Save(req, w)
	return true
}

func (a *AuthManager) ClearAuthentication(w http.ResponseWriter, req *http.Request) {
	session, _ := a.Store.Get(req, a.sessionName)
	session.Values[AUTHENTICATED_PRINCIPAL] = nil
	session.ID = ""
	session.Values = nil
	session = nil
	session.Options.MaxAge = -1
	session = sessions.NewSession(a.Store, a.sessionName)
	session.Save(req, w)
}

func (a *AuthManager) isAuthRequired(req *http.Request) bool {
	p := cleanPath(req.URL.Path)
	for _, secureURL := range a.SecuredURLs {
		if match, _ := regexp.MatchString(secureURL, p); match {
			return true
		}
	}
	return false
}

type PasswordEncoder interface {
	Encode(rawPassword string) string
	Matches(rawPassword, encodedPassword string) bool
}

type UserDetailsService interface {
	LoadUserByUsername(username string) UserDetails
}

type UserDetails interface {
	GetUsername() string
	GetPassword() string
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

// cleanPath returns the canonical path for p, eliminating . and .. elements.
// Borrowed from the net/http package.
func cleanPath(p string) string {
	if p == "" {
		return "/"
	}
	if p[0] != '/' {
		p = "/" + p
	}
	np := path.Clean(p)
	// path.Clean removes trailing slash except for root;
	// put the trailing slash back if necessary.
	if p[len(p)-1] == '/' && np != "/" {
		np += "/"
	}
	return np
}
