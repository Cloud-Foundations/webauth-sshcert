package sshautn

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/Cloud-Foundations/webauth-sshcert/lib/server/sshcertauth"
)

func generateNewTestSignerAndCert(t *testing.T) (ssh.Signer, ssh.Certificate, interface{}) {
	signerPrivateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(signerPrivateKey)
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

func generateNewTestCertSignerAndAgent(t *testing.T) (ssh.Signer, ssh.Certificate, agent.Agent, error) {
	signer, cert, userPrivateKey := generateNewTestSignerAndCert(t)

	keyring := agent.NewKeyring()
	toAdd := agent.AddedKey{
		PrivateKey:   userPrivateKey,
		Certificate:  &cert,
		LifetimeSecs: 10,
	}
	err := keyring.Add(toAdd)
	if err != nil {
		t.Fatal(err)
	}
	keyList, err := keyring.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(keyList) < 1 {
		t.Fatal("invalid Keyring")
	}
	return signer, cert, keyring, nil
}

func generateNewSSHAuthTestServer(caKeys []string, successBody string, t *testing.T) *httptest.Server {
	sa := sshcertauth.NewAuthenticator(
		[]string{"localhost", "127.0.0.1"},
		caKeys,
	)
	if sa == nil {
		t.Fatal("Did not worked well")
	}
	serveMux := http.NewServeMux()
	serveMux.HandleFunc(sshcertauth.DefaultCreateChallengePath,
		func(w http.ResponseWriter, r *http.Request) {
			err := sa.CreateChallengeHandler(w, r)
			if err != nil {
				t.Fatal(err)
			}
		},
	)
	serveMux.HandleFunc(sshcertauth.DefaultLoginWithChallengePath,
		func(w http.ResponseWriter, r *http.Request) {
			_, _, _, err := sa.LoginWithChallenge(r)
			if err != nil {
				http.Error(w, "", http.StatusInternalServerError)
			}
			if len(successBody) > 0 {
				w.Write([]byte(successBody))
			}

		},
	)
	return httptest.NewServer(serveMux)

}

func TestLoginWithKeyringAgent(t *testing.T) {
	sshSigner, _, sshAgent, err := generateNewTestCertSignerAndAgent(t)
	if err != nil {
		t.Fatal(err)
	}

	signerPub := sshSigner.PublicKey()
	testBodyStrings := []string{"", "foobar", "{somestring}"}
	for _, expectedBody := range testBodyStrings {
		ts := generateNewSSHAuthTestServer([]string{string(ssh.MarshalAuthorizedKey(signerPub))}, expectedBody, t)
		defer ts.Close()

		client := &http.Client{Timeout: 5 * time.Second}

		a, err := NewAuthenticator(ts.URL, client)
		if err != nil {
			t.Fatal(err)
		}
		returnedBody, _, err := a.DoLoginWithAgent(sshAgent)
		if err != nil {
			t.Fatal(err)
		}
		if string(returnedBody) != expectedBody {
			t.Fatal("body does not match")
		}
	}
	// Now we change the check timestamp in the far future and ensure it always fails
	for _, expectedBody := range testBodyStrings {
		ts := generateNewSSHAuthTestServer([]string{string(ssh.MarshalAuthorizedKey(signerPub))}, expectedBody, t)
		defer ts.Close()

		client := &http.Client{Timeout: 5 * time.Second}

		a, err := NewAuthenticator(ts.URL, client)
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = a.loginWithAgentAtTime(sshAgent, time.Now().Add(time.Hour*24*10))
		if err == nil {
			t.Fatal("should have Failed")
		}
	}
}

func TestLoginWithAgentIfRuning(t *testing.T) {
	socket := os.Getenv("SSH_AUTH_SOCK")
	if socket == "" {
		t.Skip("skipping test because not running agent")
	}
	conn, err := connectToDefaultSSHAgentLocation()
	if err != nil {
		t.Fatal(err)
	}
	sshSigner, cert, userPrivateKey := generateNewTestSignerAndCert(t)
	keyring := agent.NewClient(conn)
	//keyring := agent.NewKeyring()
	toAdd := agent.AddedKey{
		PrivateKey:   userPrivateKey,
		Certificate:  &cert,
		LifetimeSecs: 10,
	}
	err = keyring.Add(toAdd)
	if err != nil {
		t.Fatal(err)
	}
	signerPub := sshSigner.PublicKey()
	testBodyStrings := []string{"", "foobar", "{somestring}"}
	for _, expectedBody := range testBodyStrings {
		ts := generateNewSSHAuthTestServer([]string{string(ssh.MarshalAuthorizedKey(signerPub))}, expectedBody, t)
		defer ts.Close()

		client := &http.Client{Timeout: 5 * time.Second}

		a, err := NewAuthenticator(ts.URL, client)
		if err != nil {
			t.Fatal(err)
		}
		returnedBody, _, err := a.DoLogin()
		if err != nil {
			t.Fatal(err)
		}
		if string(returnedBody) != expectedBody {
			t.Fatal("body does not match")
		}
	}

}
