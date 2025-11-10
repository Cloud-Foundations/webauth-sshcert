package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"log"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Cloud-Foundations/webauth-sshcert/lib/client/sshautn"
	"github.com/Cloud-Foundations/webauth-sshcert/lib/server/sshcertauth"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/net/publicsuffix"
)

const testDemoPrivateKey = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACA5znC0DfyMIiOCeHfgKOO/OTzvlH6BCfTJrhRzNwTzWQAAAKAMF3nwDBd5
8AAAAAtzc2gtZWQyNTUxOQAAACA5znC0DfyMIiOCeHfgKOO/OTzvlH6BCfTJrhRzNwTzWQ
AAAEBFjWyQk/wzEQLsGMdMVKOqeLny6VV8lGuvMybvg3+ttDnOcLQN/IwiI4J4d+Ao4785
PO+UfoEJ9MmuFHM3BPNZAAAAFmN2aWVjY29AY3ZpZWNjby0tTWFjMTUBAgMEBQYH
-----END OPENSSH PRIVATE KEY-----`

const testDemoPublicKey = `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDnOcLQN/IwiI4J4d+Ao4785PO+UfoEJ9MmuFHM3BPNZ`

func generateNewTestSignerAndCert(t *testing.T) (ssh.Signer, ssh.Certificate, interface{}) {

	signer, err := ssh.ParsePrivateKey([]byte(testDemoPrivateKey))
	if err != nil {
		t.Fatal(err)
	}

	userPrivateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	userPub := userPrivateKey.Public()
	t.Logf("userPub is %T", userPub)
	sshPub, err := ssh.NewPublicKey(userPub)
	if err != nil {
		t.Fatal(err)
	}
	currentEpoch := uint64(time.Now().Unix())
	expireEpoch := currentEpoch + uint64(30)
	cert := ssh.Certificate{
		Key:             sshPub,
		CertType:        ssh.UserCert,
		SignatureKey:    signer.PublicKey(),
		ValidPrincipals: []string{"someuser"},
		ValidAfter:      currentEpoch,
		ValidBefore:     expireEpoch,
	}
	err = cert.SignCert(bytes.NewReader(cert.Marshal()), signer)
	if err != nil {
		t.Fatal(err)
	}
	return signer, cert, userPrivateKey
}

func TestBase(t *testing.T) {
	// TODO have your own testing key so that we can actually test
	server := newServer([]string{"localhost"}, []string{testDemoPublicKey})
	ts := httptest.NewTLSServer(server.HttpMux)
	defer ts.Close()

	client := ts.Client()
	res, err := client.Get(ts.URL + sshcertauth.DefaultCreateChallengePath)
	if err != nil {
		log.Fatal(err)
	}
	greeting, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s", greeting)

	res2, err := client.Get(ts.URL + sshcertauth.DefaultCreateChallengePath + "?nonce1=012345678901234567890123456789")
	if err != nil {
		log.Fatal(err)
	}

	greeting, err = io.ReadAll(res2.Body)
	res2.Body.Close()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s", greeting)

}

func TestClient(t *testing.T) {
	var err error
	sshSigner, cert, userPrivateKey := generateNewTestSignerAndCert(t)
	signerPub := ssh.MarshalAuthorizedKey(sshSigner.PublicKey())
	t.Logf("signerpub ='%s'", string(signerPub))

	//var err error
	server := newServer([]string{"localhost", "127.0.0.1"}, []string{string(signerPub)})
	ts := httptest.NewTLSServer(server.HttpMux)
	defer ts.Close()
	client := ts.Client()
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		log.Fatal(err)
	}
	client.Jar = jar

	keyring := agent.NewKeyring()
	toAdd := agent.AddedKey{
		PrivateKey:   userPrivateKey,
		Certificate:  &cert,
		LifetimeSecs: 10,
	}
	err = keyring.Add(toAdd)
	if err != nil {
		t.Fatal(err)
	}

	a, err := sshautn.NewAuthenticator(ts.URL, client)
	if err != nil {
		t.Fatal(err)
	}
	//a.LogLevel = 10
	returnedBody, _, err := a.DoLoginWithAgent(keyring)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("%s", returnedBody)

	//  /echoIdentity
	echoURL := ts.URL + "/echoIdentity"
	res, err := client.Get(echoURL)
	if err != nil {
		log.Fatal(err)
	}
	greeting, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s", greeting)

}
