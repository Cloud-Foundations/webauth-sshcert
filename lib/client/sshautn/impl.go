package sshautn

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/Cloud-Foundations/npipe"

	"github.com/Cloud-Foundations/webauth-sshcert/lib/cryptoutil"
	"github.com/Cloud-Foundations/webauth-sshcert/lib/server/sshcertauth"
)

func (s *SSHAuthenticator) loggerPrintf(level uint, format string, v ...interface{}) {
	if level <= s.LogLevel {
		log.Printf(format, v...)
	}
}

func (s *SSHAuthenticator) getChallengeNonceAndSignerList() (string, string, []string, error) {

	// Nonce should be a a base64 encoded random number (256 bytes?)
	nonce1, err := cryptoutil.GenRandomString()
	if err != nil {
		return "", "", nil, err
	}
	values := url.Values{"nonce1": {nonce1}}
	req, err := http.NewRequest("POST", s.rawBaseURL+s.getChallengePath, strings.NewReader(values.Encode()))
	if err != nil {
		return "", "", nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if s.UserAgentString != "" {
		req.Header.Set("User-Agent", s.UserAgentString)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return "", "", nil, err
	}
	defer resp.Body.Close()

	//
	// Dump response
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", "", nil, err
	}
	if resp.StatusCode >= 300 {
		return "", "", nil, fmt.Errorf("bad status response=%d", resp.StatusCode)
	}
	//log.Println(string(data))

	var newChallenge sshcertauth.ChallengeResponseData
	err = json.Unmarshal(data, &newChallenge)
	if err != nil {
		return "", "", nil, err
	}

	s.loggerPrintf(1, "challenge=%+v", newChallenge)
	return nonce1, newChallenge.Challenge, newChallenge.AllowedIssuerFingerprints, nil
}

func (s *SSHAuthenticator) doChallengerResponseCall(
	nonce1 string,
	challenge string,
	agentClient agent.Agent,
	key *agent.Key) ([]byte, http.Header, error) {

	hostname := s.baseURL.Hostname()
	signature, err := cryptoutil.WithAgentGenerateChallengeResponseSignature(
		nonce1, challenge, hostname, agentClient, key,
	)
	if err != nil {
		log.Println(err)
		return nil, nil, err
	}
	s.loggerPrintf(2, "signature(new)=%+v", signature)

	//
	values2 := url.Values{
		"nonce1":          {nonce1},
		"sshCert":         {key.String()},
		"challenge":       {challenge},
		"hostname":        {hostname},
		"signatureFormat": {signature.Format},
		"signatureBlob":   {base64.URLEncoding.EncodeToString(signature.Blob)},
	}

	req2, err := http.NewRequest("POST", s.rawBaseURL+s.loginWithChallengePath, strings.NewReader(values2.Encode()))
	if err != nil {
		return nil, nil, err
	}
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if s.UserAgentString != "" {
		req2.Header.Set("User-Agent", s.UserAgentString)
	}
	resp2, err := s.client.Do(req2)
	if err != nil {
		return nil, nil, err
	}
	defer resp2.Body.Close()

	var responseBytes []byte
	if resp2.ContentLength > 0 {
		responseBytes, err = ioutil.ReadAll(resp2.Body)
		if err != nil {
			return nil, nil, err
		}
	}
	if resp2.StatusCode >= 300 {
		return nil, nil, fmt.Errorf("bad status response=%d, data=%s", resp2.StatusCode, string(responseBytes))
	}
	s.loggerPrintf(1, "Login Success")

	return responseBytes, resp2.Header, nil

}

func connectToDefaultSSHAgentLocation() (net.Conn, error) {
	if runtime.GOOS == "windows" {
		return npipe.Dial(`\\.\pipe\openssh-ssh-agent`)
	}
	// Here we assume that all other os support unix sockets
	socket := os.Getenv("SSH_AUTH_SOCK")
	return net.Dial("unix", socket)
}

func (s *SSHAuthenticator) loginWithAgentSocket() ([]byte, http.Header, error) {
	conn, err := connectToDefaultSSHAgentLocation()
	if err != nil {
		return nil, nil, fmt.Errorf("LoginWithAgentSocket: Failed to connect to agent Socket: %v", err)
	}
	agentClient := agent.NewClient(conn)
	return s.loginWithAgent(agentClient)
}

func (s *SSHAuthenticator) loginWithAgent(agentClient agent.Agent) ([]byte, http.Header, error) {
	return s.loginWithAgentAtTime(agentClient, time.Now())
}

func (s *SSHAuthenticator) loginWithAgentAtTime(agentClient agent.Agent, loginTime time.Time) ([]byte, http.Header, error) {
	keyList, err := agentClient.List()
	if err != nil {
		return nil, nil, err
	}
	//now go remote
	nonce1, challenge, issuerFingerprints, err := s.getChallengeNonceAndSignerList()
	if err != nil {
		return nil, nil, err
	}

	lastErr := fmt.Errorf("No suitable Cert Found")
	for _, key := range keyList {
		//log.Printf("key=%+v, FORMAT=%s", key, key.Format)
		pubKey, err := ssh.ParsePublicKey(key.Marshal())
		if err != nil {
			log.Println(err)
			continue
		}
		sshCert, ok := pubKey.(*ssh.Certificate)
		if !ok {
			s.loggerPrintf(1, "SSH public key is not a certificate")
			continue
		}
		s.loggerPrintf(2, "cert=%s", key.String())
		keyFP := sshcertauth.FingerprintSHA256(sshCert.Key)
		// TODO: add a check if the current time is < unix epoch
		if sshCert.ValidBefore < uint64(loginTime.Unix()) {
			s.loggerPrintf(1, "SSH Cert (keyFP=%s) is not valid anymore, skipping", keyFP)
			continue
		}
		issuerFP := sshcertauth.FingerprintSHA256(sshCert.SignatureKey)
		knownIssuer := false
		for _, potentialSignerFP := range issuerFingerprints {
			if issuerFP == potentialSignerFP {
				knownIssuer = true
			}
		}
		if !knownIssuer {
			s.loggerPrintf(1, "Cert Issuer not trusted by remote, skipping")
			lastErr = fmt.Errorf("No local cert trusted by remote service")
			continue
		}

		//lastErr = s.loginWithCertAndAgent(agentClient, key)
		content, headers, lastErr := s.doChallengerResponseCall(nonce1, challenge, agentClient, key)
		if lastErr != nil {
			log.Printf("Error using cert %s", key.String())
			continue
		}
		return content, headers, nil

	}
	return nil, nil, fmt.Errorf("Could not login, last err=%s", lastErr)
}
