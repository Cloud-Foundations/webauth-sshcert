package main

import (
	"crypto/tls"
	"flag"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/cookiejar"
	"time"

	"github.com/cviecco/webauth-sshcert/lib/client/sshAutn"
	"golang.org/x/net/publicsuffix"
)

const message = "hello"
const randomStringEntropyBytes = 32

var (
	baseURL = flag.String("baseURL", "https://localhost:4443", "The demo server base URL")
)

func main() {
	flag.Parse()
	log.SetFlags(log.Lshortfile)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		log.Fatalf("err=%s", err)
	}
	client := &http.Client{Transport: tr, Jar: jar, Timeout: 25 * time.Second}

	authenticator, err := sshAutn.NewAuthenticator(*baseURL, client)
	if err != nil {
		log.Fatalf("err=%s", err)
	}
	authenticator.LogLevel = 1
	err = authenticator.DoLogin()
	if err != nil {
		log.Fatalf("err=%s", err)

	}
	res, err := client.Get(*baseURL + "/echoIdentity")
	if err != nil {
		log.Println(err)
	}
	//log.Printf("res=%+v", res)
	robots, err := ioutil.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("%s", robots)

}
