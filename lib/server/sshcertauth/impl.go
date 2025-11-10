package sshcertauth

import (
	"bytes"
	//"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"

	//"io"
	"log"
	//"net"
	"net/http"
	//"sync"
	"strings"
	"time"

	"github.com/Cloud-Foundations/webauth-sshcert/lib/cryptoutil"
	"golang.org/x/crypto/ssh"
)

// TODO: Marshal auth only once
// TODO: Marshal ca's just once
// TODO: remember most recenly successful ones and try those first.
func (a *Authenticator) isUserAuthority(auth ssh.PublicKey) bool {
	for _, signer := range a.caKeys {
		sshCaPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(signer))
		if err != nil {
			log.Printf("error parsing ssh PubCA, %s", err)
			continue
		}
		if bytes.Equal(sshCaPub.Marshal(), auth.Marshal()) {
			return true
		}
	}
	return false
}

// base64 sha256 hash with the trailing equal sign removed
func fingerprintSHA256(key ssh.PublicKey) string {
	hash := sha256.Sum256(key.Marshal())
	b64hash := base64.StdEncoding.EncodeToString(hash[:])
	return strings.TrimRight(b64hash, "=")
}

func (a *Authenticator) computeCAFingeprints() error {
	a.caFingerPrints = make([]string, len(a.caKeys))
	for i, signer := range a.caKeys {
		sshCaPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(signer))
		if err != nil {
			return err
		}
		a.caFingerPrints[i] = FingerprintSHA256(sshCaPub)
	}
	return nil
}

func (a *Authenticator) unsafeUpdateCaKeys(caKeys []string) error {
	a.caKeys = caKeys
	return a.computeCAFingeprints()
}

func (a *Authenticator) validateSSHCertString(encodedSSHCert string) (*ssh.Certificate, string, error) {
	if encodedSSHCert == "" {
		return nil, "Missing Parameter (sshCert)", fmt.Errorf("Missing Parameter (sshCert)")
	}
	// TODO: Validate inbound data cert (regexp + size)
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(encodedSSHCert))
	if err != nil {
		log.Printf("sshCert=%s", encodedSSHCert)
		log.Println(err)
		return nil, "Invalid SSH cert", fmt.Errorf("Invalid Ssh Cert (not valid ssh)")
	}
	sshCert, ok := pubKey.(*ssh.Certificate)
	if !ok {
		log.Printf("it is not a cert")
		return nil, "This is a key not a cert", fmt.Errorf("This is a key, not a cert")
	}
	// now we validate the cert
	//verify the cert....
	if len(sshCert.ValidPrincipals) != 1 {
		log.Printf("Too many principals in cert")
		return nil, "Number of principals in cert != 1", fmt.Errorf("Number of principals in cert != 1")
	}
	principal := sshCert.ValidPrincipals[0]
	certChecker := ssh.CertChecker{
		IsUserAuthority: a.isUserAuthority,
	}
	if sshCert.CertType != ssh.UserCert {
		return nil, "Invalid Certificate Type", fmt.Errorf("Invalid Certificate Type")
	}
	if !a.isUserAuthority(sshCert.SignatureKey) {
		return nil, "Unrecognized Issuer", fmt.Errorf("Unrecognized Issuer")
	}

	err = certChecker.CheckCert(principal, sshCert)
	if err != nil {
		log.Printf("failt to checkCert err=%s", err)
		return nil, "invalid or expired Cert", fmt.Errorf("Invalid or expired Cert: err=%s", err)
	}
	return sshCert, "", nil
}

func (a *Authenticator) createChallengeHandler(w http.ResponseWriter, r *http.Request) error {
	switch r.Method {
	case "GET":
	case "POST":
	default:
		http.Error(w, "", http.StatusMethodNotAllowed)
		return fmt.Errorf("Method not Allowed")
	}
	err := r.ParseForm()
	if err != nil {
		log.Println(err)
		http.Error(w, "", http.StatusBadRequest)
		return err
	}
	encodedNonce1 := r.Form.Get("nonce1")
	if encodedNonce1 == "" {
		http.Error(w, "", http.StatusBadRequest)
		return fmt.Errorf("Missing Parameter (Nonce1)")
	}
	// TODO: validate nonce1 is actually a valid base64 value
	///Now build response
	challenge, err := cryptoutil.GenRandomString()
	if err != nil {
		http.Error(w, "", http.StatusInternalServerError)
		return err
	}
	toStore := pendingChallengeData{
		Nonce1:     encodedNonce1,
		Expiration: time.Now().Add(ExpirationChallengeMaxAge),
		//Cert:   sshCert,
	}
	a.pendingChallengeMutex.Lock()
	a.pendingChallenges[challenge] = toStore
	a.pendingChallengeMutex.Unlock()

	returnData := ChallengeResponseData{
		Challenge:                 challenge,
		AllowedIssuerFingerprints: a.caFingerPrints,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(returnData)
	return nil
}
func (a *Authenticator) verifyHostname(hostname string) (bool, error) {
	for _, configuredHostname := range a.hostnames {
		if hostname == configuredHostname {
			return true, nil
		}
	}
	return false, nil
}

func (a *Authenticator) cleanUpExpiredChallengesAtTime(now time.Time) {
	a.pendingChallengeMutex.Lock()
	defer a.pendingChallengeMutex.Unlock()
	for key, challengeData := range a.pendingChallenges {
		if challengeData.Expiration.Before(now) {
			delete(a.pendingChallenges, key)
		}
	}
}

func (a *Authenticator) cleanUpExpiredChallengesLoop() {
	for {
		a.cleanUpExpiredChallengesAtTime(time.Now())
		time.Sleep(time.Second * 5)
	}
}

func (a *Authenticator) loginWithChallenge(r *http.Request) (string, time.Time, string, error) {
	switch r.Method {
	case "GET":
	case "POST":
	default:
		return "", time.Time{}, "Invalid Method", fmt.Errorf("method not allowed")
	}
	err := r.ParseForm()
	if err != nil {
		log.Println(err)
		//state.writeFailureResponse(w, r, http.StatusBadRequest, "Error parsing form")
		//http.Error(w, "", http.StatusBadRequest)
		//return
		return "", time.Time{}, "", err
	}
	encodedNonce2 := r.Form.Get("challenge")
	if encodedNonce2 == "" {
		return "", time.Time{}, "Missing parameter challenge", fmt.Errorf("Missing parameter challenge")

	}
	hostname := r.Form.Get("hostname")
	if hostname == "" {
		return "", time.Time{}, "Missing parameter hostname", fmt.Errorf("Missing parameter hostname")

	}
	valid, err := a.verifyHostname(hostname)
	if err != nil {
		return "", time.Time{}, "", err
	}
	if !valid {
		return "", time.Time{}, "Invalid hostname", fmt.Errorf("Invalid hostname")
	}

	signatureFormat := r.Form.Get("signatureFormat")
	if signatureFormat == "" {
		//http.Error(w, "", http.StatusBadRequest)
		//return
		return "", time.Time{}, "Missing parameter signatureFormat", fmt.Errorf("Missing parameter signatureFormat")
	}
	// TODO: validate the signature format is sane
	encodedSignatureBlob := r.Form.Get("signatureBlob")
	if encodedSignatureBlob == "" {
		//http.Error(w, "", http.StatusBadRequest)
		//return
		return "", time.Time{}, "Missing parameter signatureBlob", fmt.Errorf("Missing parameter signatureBlob")
	}
	signatureBlob, err := base64.URLEncoding.DecodeString(encodedSignatureBlob)
	if err != nil {
		//http.Error(w, "Invalid Signature Data", http.StatusBadRequest)
		//return
		return "", time.Time{}, "Missing bad signature Format", err
	}

	encodedSSHCert := r.Form.Get("sshCert")
	sshCert, userErrText, err := a.validateSSHCertString(encodedSSHCert)
	if err != nil {
		//http.Error(w, "", http.StatusBadRequest)
		return "", time.Time{}, userErrText, err
	}

	a.pendingChallengeMutex.Lock()
	challengeData, ok := a.pendingChallenges[encodedNonce2]
	a.pendingChallengeMutex.Unlock()
	if !ok {
		log.Printf("challenge not found")
		//http.Error(w, "", http.StatusBadRequest)
		//return
		return "", time.Time{}, "Challenge not found/invalid", fmt.Errorf("Challenge Not Found")
	}

	if challengeData.Expiration.Before(time.Now()) {
		log.Printf("Expired Challenge")
		a.pendingChallengeMutex.Lock()
		delete(a.pendingChallenges, encodedNonce2)
		a.pendingChallengeMutex.Unlock()
		return "", time.Time{}, "Challenge expired", fmt.Errorf("Expired Challenge expiration=%s, now=%s", challengeData.Expiration, time.Now())
	}
	err = cryptoutil.VerifyChallengeResponseSignature(sshCert,
		signatureFormat, signatureBlob,
		challengeData.Nonce1, encodedNonce2, hostname)
	if err != nil {
		log.Println(err)
		//http.Error(w, "", http.StatusUnauthorized)
		return "", time.Time{}, "Unauthorized", fmt.Errorf("Invalid signature %s", err)
	}

	//we have checked before this exists
	authUser := sshCert.ValidPrincipals[0]

	// TODO check for certificates too far away in the future
	authExpiration := time.Unix(int64(sshCert.ValidBefore), 0)
	maxAge := time.Now().Add(time.Duration(24) * time.Hour)
	if authExpiration.After(maxAge) {
		authExpiration = maxAge
	}
	return authUser, authExpiration, "", nil
}
