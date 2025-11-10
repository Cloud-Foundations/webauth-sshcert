package sshcertauth

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Cloud-Foundations/webauth-sshcert/lib/cryptoutil"
)

// ssh-keygen -f /tmp/deleteme_rsa
const testUserPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAvJq2TMC6oSj7Y+xXBS+L4JnHtrjSEqIaAMTda/2HldiQSaVF
wiNC6TihJqOek9UGNmNJbpezJcvbM6t7cssyRr1EkaU5NJ+6YpUFCLLJMOjRJ7ce
fak4Rf6GabC5SSMa8qth1qEcdJbwJi9sgbTNpMxM6GBQLkjXvefvC+pInNAYORnF
lnr3JJDMJd/EbVQb2LHcACwelbyo6VeR2NSxDwHcQ6rXUd36pRKSAfR8FBtqShmi
OLaHHec0NBBj1S0WnAaLdk38rHjAZtOPuyzqNGkm/8mnwHWGNnr+G6Werer2ij/9
JpbJ8Ee38yBCJ+HBpzILyup2bxsM9/8uhss6HwIDAQABAoIBAByCurohjFTecBor
2P/Erz11obYifEcq0Al7uQkhG0TwpucrH794Ox4sXFgN9ePdGQJRwgEA16kIBwvp
iVDSHLiK1fm6Y0psNu2+HzOway+EklGRof9W/FXAYytI9slykBlNBQ4/7qBFTOpI
0vtMjKWz6JBcNuK4Sjy/+efwM6fYnsxnyi30rtj8iv4YTzepO46b9KiIc4ByhVgd
UbK1quHQTk+dIlVSQaJCssGftLoyB9jqfLfOSkMOze6TSJwXXSTJ4Wz0Y5xGMOEZ
4l8xa/E4o69J5GOpWdV95ieiCkEt8DqFoNg0FgHB785CvgBFeVVczLNYUooRTzsT
EoPuudECgYEA4VPi0+lxMNdvFyHNeoyc8FI2doZUxKbnlrFRpLzPo2Sm8kVl9d+O
PkJ5uStT106Z0+1Y5y2MHArnfdErGl2dN2LIoLlCkufJfSKxq8LXgs8NZYUjZDB5
aC7lSnUzOP1cvM+MQ3ZZ35tRIYYFtIYh/oZypER4fLnJmN3fnP7R6gcCgYEA1kcb
vrMWn1EZ2ihlJoDPeuktw+JCVE1oQ1MqB6wsZJRwDFZLpvVH4a9pZ12Ag9p+qpIh
W2aqgcdjbjRaB1uafHvbiY6qf1PsMLSLOrAqvO/FG/KpruOIhVFDLUrqWdLDXlVI
UtKOQVccBAKGK+CocEnAuHqpVA/QmyMHx7fZiSkCgYEArMn3FynccufBeKujNma9
skxZF2rLdkHHNfej9AAV+eYlX4N4PKPCIFw5m5VuJZ1QuQM5OY3j810pR4Iu23kO
JnrJ/vYR5zV3fU4tkNlJCjZcv4zpJttFPm83xXE6ZmljxCYkGVeYc7BW9q4fkd+K
EfRn1S/sdTjDL0Z1Q57kueECgYEAt1F2hxuoCvzTZTSR9PLWjozXPnJf1Me0n4SS
vKWsBRCJG8ToTBokOQxc3LW9sRBItZz3NL8MuKLgifP34buY208Lbw/DBdPCiZis
VLVKmwF2XIaqbJj0vznagvFItTf/NME5csH4OiZQLY4LQ5acBBTU7/7gxq4RBehe
S5saXKECgYEAwe39pvRbkMA353uNHf2Dkj4STrJGbnc/SuritI3J5H3BfGkGmovG
M58D6oPPabTf/LGfl3089j9AmOyA1aUqoCqSKiAb4DrrpzQndYsxjumD0plHM35X
h12wHUZrzYUWojD0c7UbP8jJAACJkfREFhUQVdrY1xTvlD46Zd91NIE=
-----END RSA PRIVATE KEY-----`

// actual output SHA256:1sTu4EM0wYab///MibgBWdN20XNHAVc2v9ChbJNUWqc cviecco@XXXXXX
const testUserPrivateKeySHA256 = `1sTu4EM0wYab///MibgBWdN20XNHAVc2v9ChbJNUWqc`

// and example signer
const exampleSignerPub = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQD6+x+wPjuKWM7A8aCZgGdiFXRZdpLRZk+KpvNBe9nXu9GHznWYrPIXWVCLl+yp6v30ldzRUiCzHnskV0R4Wzjxi2LCKlVIwpx2Z7gVk8XnZf/MAHdvklfHB2srpWsGUQNJhxCVeOFweJxhLSILkh6y+V0yZ8Zy3t2ALCrHAyOEYhz/RgHgmWMYvxzoSj5wnS16tY3Adt3sOu3DMRq45dIsKjN0bjSPjycL6TQGWvE9BK8HsioyEVCNItWbh4+4kfr4L32U6Sw9syvK4P29kvHnPbSoLssCKuWvtKaLjI9qKFj+sL3hlsZCU5kvHEPVWDudExW2wA8hm6S2wpIOqI/Ua/24Dhm7MKimeqXiOoO0wzPeh7IaKQfczy68Hmk2S8oubj8wIwjxZICbhL/cxl7ZD1EWY/LZH+g5bf98gvl0mC3gFWEVyA4ZZwNkzIlV1NZXibXkdsquJg24/+ZMMtMat/kqd8di9lzuoVRAOV9q80v7QFi25jHjKgXTJ7Av7mc="

const testIssuerPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAv+SQMn4FikGnxdzEpFAX2NfgkgRsgx/4vOhT14zmWLEuG6+l
3T6xoW3iGGOdkw5+KG1UMaqhWV35Tk4PVBRre/Ijymo9y+MXSBZPiodnilOViwbv
X8vtf0+nHbhAnSki0BrzWfFHyXelKxuLfCbq3iZasL3xgAuYJ/phcptrepQ7lV3z
OhNB30jFBjojkBflCwUPJzVDWgBU6TL5oIRccyZzbrhMC7P7niyqYzm1t+Wx3uAc
hWmRBi9KxZ7BmtVzhQvwLvYkprOS9PscGdiAL8iYtexgfdET5WXJuThWQpdxdGRY
XQrv0zWDND4JR36yvA5jel5/6D+CQs1oIe+9EwIDAQABAoIBAAYRG938zgAJA1zm
FfF79sUMTjVPnn6mzB5s2fm+oqm7MFH/w6azDLql1rgeriSwGJz+l+LaGi/RIMiw
/xsRajSI+0izAzEnBN1qlykyDrv42ImEtpy4vdGAmy/9W02ct1UNBRSa5EIiXj52
qHpMYLCVVdiwqKn7s9vPtrUA5O0DJLcQne3by/IoXZvkpHAWw5iFQM5rkCeN3SAC
AaDVqvV/E39FNu8P4lMm0m5dbMwRpxAajaQurpS2Bu2VFf+hmjsc3siwAI4Ampfx
wrJCq6uSv2qWjkPdZpjEQY30dO9qXO8Hn6gEk37LDtzEv2Y0tAhbDT1y3tDcaM/k
KQW4k8ECgYEA6K2hPEztRqH6joShn7Mtym0pdKe+5TFJYMyiJlIpZ5Tihn8nAN6v
xtnoh5rjpULw1EAw4symdFdsJbyzocf4wAlN6vkSewF0Uuoq9tMfG3+5H2Z/hQBS
wruzsYT0Cxs05Cj1YycoKd+yCI7QVMI0kmSwxBCZOv2Ezw2qNX2URO0CgYEA0yBo
FQOrMdrrZmmYeWTroCQtemoqb5C+SGPWzQZJr0nAV+OeXW1o2nIV+prjBGlJe4yx
ex0L6dqr9iIfEWcsiGYbr4Uc1l7tI0923KABza1KaNYZuZXAPKHuGehnhP31SekE
XwPxKlp82Y4/uRkLlFl0p0I4YxjJUc+0YdqFyf8CgYA+56ItoUaM0AHjQexINrLs
hTKt/SPY5shFyU0VOyVCgbf0ULAExi+TfRomfzOIXF6ro2cUCev+jBwK38dYt62C
jYFpQ0lBxBTkzbYr4MwKLS+pU5aqKHo3d3OPTLiFwCc+f+xHkDCFkZqaQbIFGDQK
V/qKJ0ql7iBXsgQQThElyQKBgQCVi23N/MRFUxDMgN1cl0yDKT0BabPXRIpT0kwy
+1I0FCRm3Lau7LGJkafZ094boMxI9DY+wytOIPMPK8of1Jnpn5HauIndmm2URlQm
IDxGyIldStH774O0LurtdP3maNBW4vOSrcMkQeYPX7/pR0E5ekeztaclIkhvZ5UY
fuWnVwKBgGj9PZqGK6y8jamQKbKwFhCM2JQcIM+taeAFYlNgg7MFEnK3R/LBmYSd
v0U5lsWBjVpg5Kl93VpXLTWLPfVQ0RLFP5xMn/hMA8EfJr710BG8X7SMw+diCe+H
li680TcWMAl3V2KeKpvCMnFj/b7i/1SCMifN8kYt5ga039w25SEK
-----END RSA PRIVATE KEY-----`

// Copied from keymaster's lib/certutil
func getSignerFromPEMBytes(privateKey []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(privateKey)
	if block == nil {
		err := fmt.Errorf("Cannot decode Private Key")
		return nil, err
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		parsedIface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		switch v := parsedIface.(type) {
		case *rsa.PrivateKey:
			return v, nil
		case *ecdsa.PrivateKey:
			return v, nil
		default:
			return nil, fmt.Errorf("Type (%T) not regocnized", v)
		}
	default:
		err := fmt.Errorf("Cannot process that key")
		return nil, err
	}
}

func goCertToFileString(c ssh.Certificate) string {
	certBytes := c.Marshal()
	encoded := base64.StdEncoding.EncodeToString(certBytes)
	fileComment := "/somecert"
	// TODO: do not assume is an rsa cert
	return "ssh-rsa-cert-v01@openssh.com " + encoded + " " + fileComment
}

func getTestCertSigner() (crypto.Signer, ssh.Signer, []byte, error) {
	cryptoSigner, err := getSignerFromPEMBytes([]byte(testIssuerPrivateKey))
	if err != nil {
		return nil, nil, nil, err
	}
	sshSigner, err := ssh.NewSignerFromSigner(cryptoSigner)
	if err != nil {
		return nil, nil, nil, err
	}
	sshPub := sshSigner.PublicKey()
	ssh.MarshalAuthorizedKey(sshPub)
	return cryptoSigner, sshSigner, ssh.MarshalAuthorizedKey(sshPub), nil

}

func TestFingerprintSHA256(t *testing.T) {
	signer, err := getSignerFromPEMBytes([]byte(testUserPrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	sshSigner, err := ssh.NewSignerFromSigner(signer)
	if err != nil {
		t.Fatal(err)
	}
	computedFP := FingerprintSHA256(sshSigner.PublicKey())
	if computedFP != testUserPrivateKeySHA256 {
		t.Fatalf("expected does not match expacted=%s, computed=%s", testUserPrivateKeySHA256, computedFP)
	}

}

func TestNewAuthenticator(t *testing.T) {
	authenticator := NewAuthenticator([]string{"localhost"}, []string{exampleSignerPub})
	if authenticator == nil {
		t.Fatal("Did not worked well")
	}
	// TODO: check with invalid signer string
}

func TestUnsafeUpdateCaKeys(t *testing.T) {
	//emtyp
	authenticator := NewAuthenticator([]string{"localhost"}, []string{})
	if authenticator == nil {
		t.Fatal("Did not worked well")
	}
	if len(authenticator.caKeys) != 0 {
		t.Fatalf("there should be no keys")
	}
	keyset := []string{exampleSignerPub}
	err := authenticator.UnsafeUpdateCaKeys(keyset)
	if err != nil {
		t.Fatal(err)
	}
	if len(authenticator.caKeys) != 1 {
		t.Fatalf("there should be only one key")
	}

	//shour error with invalid value
	err = authenticator.UnsafeUpdateCaKeys([]string{"thisisnokey"})
	if err == nil {
		t.Fatal("shot have failed to update with bad key")
	}
}

func TestIsUserAuthority(t *testing.T) {
	_, signer, signerPub, err := getTestCertSigner()
	if err != nil {
		t.Fatal(err)
	}
	a := NewAuthenticator([]string{"localhost"}, []string{string(signerPub)})
	if a == nil {
		t.Fatal("Did not worked well")
	}
	valid := a.isUserAuthority(signer.PublicKey())
	if !valid {
		t.Fatal("should have validated")
	}
	a2 := NewAuthenticator([]string{"localhost"}, []string{exampleSignerPub})
	valid = a2.isUserAuthority(signer.PublicKey())
	if valid {
		t.Fatal("should NOT have validated")
	}

}

func TestValidateSSHCertString(t *testing.T) {
	_, signer, signerPub, err := getTestCertSigner()
	if err != nil {
		t.Fatal(err)
	}
	a := NewAuthenticator([]string{"localhost"}, []string{string(signerPub)})
	if a == nil {
		t.Fatal("Did not worked well")
	}

	// Generate user cert with signer
	userPrivateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	userPub := userPrivateKey.Public()
	sshPub, err := ssh.NewPublicKey(userPub)
	if err != nil {
		t.Fatal(err)
	}
	currentEpoch := uint64(time.Now().Unix())
	expireEpoch := currentEpoch + uint64(30)
	cert := ssh.Certificate{
		Key:             sshPub,
		CertType:        ssh.UserCert,
		ValidPrincipals: []string{"someuser"},
		SignatureKey:    signer.PublicKey(),
		ValidAfter:      currentEpoch,
		ValidBefore:     expireEpoch,
	}
	err = cert.SignCert(bytes.NewReader(cert.Marshal()), signer)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = a.validateSSHCertString(goCertToFileString(cert))
	if err != nil {
		t.Fatal(err)
	}
	//now an expired one
	expiredCert := ssh.Certificate{
		Key:             sshPub,
		CertType:        ssh.UserCert,
		ValidPrincipals: []string{"someuser"},
		SignatureKey:    signer.PublicKey(),
		ValidAfter:      currentEpoch - 7200,
		ValidBefore:     currentEpoch - 3600,
	}
	err = expiredCert.SignCert(bytes.NewReader(expiredCert.Marshal()), signer)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = a.validateSSHCertString(goCertToFileString(expiredCert))
	if err == nil {
		t.Fatal("should not have validated expired cert")
	}
	//now with an unstrusted signer
	untrustedSignerKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	untrustedSigner, err := ssh.NewSignerFromSigner(untrustedSignerKey)
	if err != nil {
		t.Fatal(err)
	}
	untrustedCert := ssh.Certificate{
		Key:             sshPub,
		CertType:        ssh.UserCert,
		ValidPrincipals: []string{"someuser"},
		SignatureKey:    untrustedSigner.PublicKey(),
		ValidAfter:      currentEpoch,
		ValidBefore:     expireEpoch,
	}
	err = untrustedCert.SignCert(bytes.NewReader(untrustedCert.Marshal()), untrustedSigner)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = a.validateSSHCertString(goCertToFileString(untrustedCert))
	if err == nil {
		t.Fatal("should not have validated untrusted cert")
	}
	//now evil issuer signs a cert with the public key of the good one
	invalidSignerCert := ssh.Certificate{
		Key:             sshPub,
		CertType:        ssh.UserCert,
		ValidPrincipals: []string{"someuser"},
		SignatureKey:    signer.PublicKey(),
		ValidAfter:      currentEpoch,
		ValidBefore:     expireEpoch,
	}
	err = invalidSignerCert.SignCert(bytes.NewReader(invalidSignerCert.Marshal()), untrustedSigner)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = a.validateSSHCertString(goCertToFileString(invalidSignerCert))
	if err == nil {
		t.Fatal("should not have validated invalid signed cert")
	}
	// Now a cert with the right signer but invalid type
	invalidTypeCert := cert
	invalidTypeCert.CertType = ssh.HostCert
	err = invalidTypeCert.SignCert(bytes.NewReader(invalidTypeCert.Marshal()), signer)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = a.validateSSHCertString(goCertToFileString(invalidTypeCert))
	if err == nil {
		t.Fatal("should not have validated bad type cert")
	}
	// now cert with no Valid principals
	noPrincipalsCert := ssh.Certificate{
		Key:          sshPub,
		CertType:     ssh.UserCert,
		SignatureKey: signer.PublicKey(),
		ValidAfter:   currentEpoch,
		ValidBefore:  expireEpoch,
	}
	err = noPrincipalsCert.SignCert(bytes.NewReader(noPrincipalsCert.Marshal()), signer)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = a.validateSSHCertString(goCertToFileString(noPrincipalsCert))
	if err == nil {
		t.Fatal("should not have validated cert with no principals")
	}

	// now a key not a cert
	_, _, err = a.validateSSHCertString(string(signerPub))
	if err == nil {
		t.Fatal("should not have validated a key")
	}
	// now with empty string
	_, _, err = a.validateSSHCertString("")
	if err == nil {
		t.Fatal("should not have validated empty string")
	}
	// now with a non-cert-non ssh string
	_, _, err = a.validateSSHCertString("hello")
	if err == nil {
		t.Fatal("should not have validated non ssh string")
	}

}

func TestCreateChallengeHandlerAndLogin(t *testing.T) {
	_, signer, signerPub, err := getTestCertSigner()
	if err != nil {
		t.Fatal(err)
	}
	a := NewAuthenticator([]string{"localhost"}, []string{string(signerPub)})
	if a == nil {
		t.Fatal("Did not worked well")
	}
	nonce, err := cryptoutil.GenRandomString()
	if err != nil {
		t.Fatal(err)
	}
	v := url.Values{}
	v.Set("nonce1", nonce)
	targetURL := "/someURL" //TODO need to make this a const
	req, err := http.NewRequest("POST", targetURL, bytes.NewBufferString(v.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
	//t.Logf("req=%+v", req)
	w := httptest.NewRecorder()
	err = a.CreateChallengeHandler(w, req)
	if err != nil {
		t.Fatal(err)
	}
	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("did not return valid status code, got %d", resp.StatusCode)
	}
	defer resp.Body.Close()
	//
	// Dump response
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	var jsonChallenge ChallengeResponseData
	err = json.Unmarshal(data, &jsonChallenge)
	if err != nil {
		t.Fatal(err)
	}

	//Now we generate a cert

	// Generate user cert with signer
	userPrivateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	userPub := userPrivateKey.Public()
	sshPub, err := ssh.NewPublicKey(userPub)
	if err != nil {
		t.Fatal(err)
	}
	currentEpoch := uint64(time.Now().Unix())
	expireEpoch := currentEpoch + uint64(30)
	cert := ssh.Certificate{
		Key:             sshPub,
		CertType:        ssh.UserCert,
		ValidPrincipals: []string{"someuser"},
		SignatureKey:    signer.PublicKey(),
		ValidAfter:      currentEpoch,
		ValidBefore:     expireEpoch,
	}
	err = cert.SignCert(bytes.NewReader(cert.Marshal()), signer)
	if err != nil {
		t.Fatal(err)
	}
	certString := goCertToFileString(cert)
	_, _, err = a.validateSSHCertString(certString)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := cryptoutil.WithCertAndPrivateKeyGenerateChallengeResponseSignature(
		nonce,
		jsonChallenge.Challenge,
		"localhost",
		&cert,
		userPrivateKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	values2 := url.Values{
		"nonce1":          {nonce},
		"sshCert":         {certString},
		"challenge":       {jsonChallenge.Challenge},
		"hostname":        {"localhost"},
		"signatureFormat": {signature.Format},
		"signatureBlob":   {base64.URLEncoding.EncodeToString(signature.Blob)},
	}
	req2, err := http.NewRequest("POST", "loginChallengePath", strings.NewReader(values2.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	authUser, _, _, err := a.LoginWithChallenge(req2)
	if err != nil {
		t.Fatal(err)
	}
	if authUser != "someuser" {
		t.Fatal("mismatch user auth")
	}

}

func TestCleanUpExpiredChallengesAtTime(t *testing.T) {
	_, _, signerPub, err := getTestCertSigner()
	if err != nil {
		t.Fatal(err)
	}
	a := NewAuthenticator([]string{"localhost"}, []string{string(signerPub)})
	if a == nil {
		t.Fatal("Did not worked well")
	}
	now := time.Now()
	a.pendingChallengeMutex.Lock()
	seconds := []int{30, 60, 120}
	for index, sec := range seconds {
		toStore := pendingChallengeData{
			//Nonce1:     encodedNonce1,
			Expiration: now.Add(time.Second * time.Duration(sec)),
		}
		a.pendingChallenges[strconv.FormatInt(int64(index), 10)] = toStore
	}
	a.pendingChallengeMutex.Unlock()

	expectedLengths := []int{3, 3, 2, 1, 1, 1, 0}
	a.cleanUpExpiredChallengesAtTime(now)
	for i, expectedLen := range expectedLengths {
		a.cleanUpExpiredChallengesAtTime(now.Add(time.Second * time.Duration(i*20+1)))
		a.pendingChallengeMutex.Lock()
		pendingLen := len(a.pendingChallenges)
		a.pendingChallengeMutex.Unlock()
		if pendingLen != expectedLen {
			errstr := fmt.Sprintf("unexpected len=%d i=%d, expected=%d", pendingLen, i, expectedLen)
			t.Fatalf("%s", errstr)
		}
	}
}

func TestCreateChallengeHandlerBadParams(t *testing.T) {
	_, _, signerPub, err := getTestCertSigner()
	if err != nil {
		t.Fatal(err)
	}
	a := NewAuthenticator([]string{"localhost"}, []string{string(signerPub)})
	if a == nil {
		t.Fatal("Did not worked well")
	}
	nonce, err := cryptoutil.GenRandomString()
	if err != nil {
		t.Fatal(err)
	}
	v := url.Values{}
	v.Set("nonce1", nonce)
	// Test Bad Method
	targetURL := "/someURL" //TODO need to make this a const
	req, err := http.NewRequest("FOOO", targetURL, bytes.NewBufferString(v.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
	//t.Logf("req=%+v", req)
	w := httptest.NewRecorder()
	err = a.CreateChallengeHandler(w, req)
	if err == nil {
		t.Fatal("should have failed")
	}

	// no nonce
	v2 := url.Values{}
	req2, err := http.NewRequest("FOOO", targetURL, bytes.NewBufferString(v2.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
	//t.Logf("req=%+v", req)
	w2 := httptest.NewRecorder()
	err = a.CreateChallengeHandler(w2, req2)
	if err == nil {
		t.Fatal("should have failed")
	}
}
