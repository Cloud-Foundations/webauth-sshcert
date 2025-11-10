package main

import (
	//"bytes"
	//"bufio"
	"crypto/rand"
	"os"
	"strings"

	//"crypto/sha256"
	//"crypto/tls"
	"encoding/base64"
	//"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"

	//"net"
	"net/http"
	"sync"
	"time"

	"github.com/Cloud-Foundations/webauth-sshcert/lib/server/sshcertauth"
	//"golang.org/x/crypto/ssh"
)

type authCookieStruct struct {
	Username  string
	ExpiresAt time.Time
}

// Server this is the demo server and associated structs
type Server struct {
	authenticator *sshcertauth.Authenticator
	authCookie    map[string]authCookieStruct
	cookieMutex   sync.Mutex
	HttpMux       *http.ServeMux
}

var (
	listenAddr             = flag.String("addr", "127.0.0.1:4443", "listening Address")
	trustedIssuersFilename = flag.String("trustedIssuers", "", "name of trustedIssuers")
)

const authCookieName = "demo-auth-cookie"
const cookieExpirationHours = 1

const trustedSigner = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQD6+x+wPjuKWM7A8aCZgGdiFXRZdpLRZk+KpvNBe9nXu9GHznWYrPIXWVCLl+yp6v30ldzRUiCzHnskV0R4Wzjxi2LCKlVIwpx2Z7gVk8XnZf/MAHdvklfHB2srpWsGUQNJhxCVeOFweJxhLSILkh6y+V0yZ8Zy3t2ALCrHAyOEYhz/RgHgmWMYvxzoSj5wnS16tY3Adt3sOu3DMRq45dIsKjN0bjSPjycL6TQGWvE9BK8HsioyEVCNItWbh4+4kfr4L32U6Sw9syvK4P29kvHnPbSoLssCKuWvtKaLjI9qKFj+sL3hlsZCU5kvHEPVWDudExW2wA8hm6S2wpIOqI/Ua/24Dhm7MKimeqXiOoO0wzPeh7IaKQfczy68Hmk2S8oubj8wIwjxZICbhL/cxl7ZD1EWY/LZH+g5bf98gvl0mC3gFWEVyA4ZZwNkzIlV1NZXibXkdsquJg24/+ZMMtMat/kqd8di9lzuoVRAOV9q80v7QFi25jHjKgXTJ7Av7mc="

func randomStringGeneration() (string, error) {
	const size = 32
	bytes := make([]byte, size)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

func (s *Server) setAndStoreAuthCookie(w http.ResponseWriter, username string, maxAge time.Time) error {
	randomString, err := randomStringGeneration()
	if err != nil {
		log.Println(err)
		return err
	}
	expires := time.Now().Add(time.Hour * cookieExpirationHours)
	if expires.After(maxAge) {
		expires = maxAge
	}
	userCookie := http.Cookie{Name: authCookieName, Value: randomString, Path: "/", Expires: expires, HttpOnly: true, Secure: true}
	http.SetCookie(w, &userCookie)
	Cookieinfo := authCookieStruct{username, userCookie.Expires}
	s.cookieMutex.Lock()
	s.authCookie[userCookie.Value] = Cookieinfo
	s.cookieMutex.Unlock()
	return nil
}

func (s *Server) getRemoteUserName(w http.ResponseWriter, r *http.Request) (string, error) {

	//setupSecurityHeaders(w)

	remoteCookie, err := r.Cookie(authCookieName)
	if err != nil {
		//s.logger.Debugf(1, "Err cookie %s", err)
		http.Error(w, "", http.StatusUnauthorized)
		return "", err
	}
	s.cookieMutex.Lock()
	defer s.cookieMutex.Unlock()
	authInfo, ok := s.authCookie[remoteCookie.Value]
	if !ok {
		//s.oauth2DoRedirectoToProviderHandler(w, r)
		http.Error(w, "", http.StatusUnauthorized)
		return "", fmt.Errorf("Cookie not found")
	}
	if authInfo.ExpiresAt.Before(time.Now()) {
		//s.oauth2DoRedirectoToProviderHandler(w, r)
		http.Error(w, "", http.StatusUnauthorized)
		return "", fmt.Errorf("Expired Cookie")
	}
	return authInfo.Username, nil
}

func (s *Server) echoIdentityHandler(w http.ResponseWriter, r *http.Request) {
	authUser, err := s.getRemoteUserName(w, r)
	if err != nil {
		log.Printf("failure getting username")
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	outString := fmt.Sprintf("hello %s\n", authUser)
	io.WriteString(w, outString)
}

// CreateChallengeHandler is an example of how to write a handler for
// the path to create the challenge
func (s *Server) CreateChallengeHandler(w http.ResponseWriter, r *http.Request) {
	err := s.authenticator.CreateChallengeHandler(w, r)
	if err != nil {
		log.Printf("there was an err: %s", err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
}

// LoginWithChallengeHandler is an example on how to handle the call to login withChallenge
// path. Notice that we fist do the authentication checks, then we create the session
// and we finalize with setting a cookie (which in this implementaiton) is used to track
// user sessions.
func (s *Server) LoginWithChallengeHandler(w http.ResponseWriter, r *http.Request) {
	authUser, maxAge, userErrString, err := s.authenticator.LoginWithChallenge(r)
	if err != nil {
		log.Printf("error=%s", err)
		errorCode := http.StatusBadRequest
		if userErrString == "" {
			errorCode = http.StatusInternalServerError
		}
		http.Error(w, userErrString, errorCode)
		return
	}
	err = s.setAndStoreAuthCookie(w, authUser, maxAge)
	if err != nil {
		log.Println(err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
	log.Printf("Success auth %s", authUser)
}

func newServer(allowedHostnames []string, trustedSSHCA []string) *Server {
	server := Server{
		authenticator: sshcertauth.NewAuthenticator(allowedHostnames, trustedSSHCA),
		authCookie:    make(map[string]authCookieStruct),
		HttpMux:       http.NewServeMux(),
	}
	server.HttpMux.HandleFunc("/echoIdentity", server.echoIdentityHandler)
	server.HttpMux.HandleFunc(sshcertauth.DefaultCreateChallengePath, server.CreateChallengeHandler)
	server.HttpMux.HandleFunc(sshcertauth.DefaultLoginWithChallengePath, server.LoginWithChallengeHandler)
	return &server
}

func main() {
	flag.Parse()
	log.SetFlags(log.Lshortfile)

	var trustedSigners []string
	if (*trustedIssuersFilename) != "" {
		content, err := os.ReadFile(*trustedIssuersFilename)
		if err != nil {
			log.Fatal(err)
		}
		trustedSigners = strings.Split(string(content), "\n")
	} else {
		trustedSigners = append(trustedSigners, trustedSigner)
	}
	//log.Printf("trustedSigners=%+v", trustedSigners)

	server := newServer([]string{"localhost"}, trustedSigners)
	err := http.ListenAndServeTLS(*listenAddr, "server.crt", "server.key", server.HttpMux)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}

}
