package attest

import (
	"archive/zip"
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

type Verifier struct {
	rootCert    *x509.Certificate
	currentTime time.Time
}

type VerifierOpt func(*Verifier)

func NewVerifier(opts ...VerifierOpt) *Verifier {
	v := new(Verifier)
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// WithRootCert sets the root certificate to use. By default attestation uses
// the aws root certificate.
func WithRootCert(rootCert *x509.Certificate) VerifierOpt {
	return func(v *Verifier) {
		v.rootCert = rootCert
	}
}

func WithCurrentTime(time time.Time) VerifierOpt {
	return func(v *Verifier) {
		v.currentTime = time
	}
}

type sign1Message struct {
	_           struct{} `cbor:",toarray"`
	Protected   cbor.RawMessage
	Unprotected cbor.RawMessage
	Payload     []byte
	Signature   []byte
}

type AttestationDoc struct {
	ModuleID    string `cbor:"module_id"`
	Timestamp   uint64
	Digest      string
	PCRs        map[int][]byte
	Certificate []byte
	Cabundle    [][]byte
	PublicKey   []byte `cbor:"public_key"`
	UserData    []byte `cbor:"user_data"`
	Nonce       []byte `cbor:"nonce"`
}

var ErrValidatingNonce = errors.New("error validating nonce")

func createSign1(d []byte) (*cose.Sign1Message, error) {
	var m sign1Message
	err := cbor.Unmarshal(d, &m)
	if err != nil {
		return nil, err
	}
	msg := &cose.Sign1Message{
		Headers: cose.Headers{
			RawProtected:   m.Protected,
			RawUnprotected: m.Unprotected,
		},
		Payload:   m.Payload,
		Signature: m.Signature,
	}
	if err := msg.Headers.UnmarshalFromRaw(); err != nil {
		return nil, err
	}

	return msg, nil
}

func verifySignature(cert *x509.Certificate, msg *cose.Sign1Message) error {
	publicKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("public key must be ecdsa")
	}

	verifier, err := cose.NewVerifier(cose.AlgorithmES384, publicKey)
	if err != nil {
		return err
	}

	return msg.Verify([]byte{}, verifier)
}

func verifyCertChain(cert *x509.Certificate, rootCert *x509.Certificate, cabundle [][]byte, currentTime time.Time) error {
	roots := x509.NewCertPool()

	roots.AddCert(rootCert)

	intermediates := x509.NewCertPool()
	for _, certBy := range cabundle {
		cert, err := x509.ParseCertificate(certBy)
		if err != nil {
			return err
		}

		intermediates.AddCert(cert)
	}

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   currentTime,
	}

	if _, err := cert.Verify(opts); err != nil {
		return err
	}

	return nil
}

func (v *Verifier) Verify(attestation []byte, nonce []byte) (*AttestationDoc, error) {
	msg, err := createSign1(attestation)
	if err != nil {
		return nil, err
	}

	doc := &AttestationDoc{}
	err = cbor.Unmarshal(msg.Payload, doc)
	if err != nil {
		log.Errorf("Error unmarshalling cbor document: %v", err)
		return nil, err
	}

	if nonce != nil && !bytes.Equal(nonce, doc.Nonce) {
		return nil, ErrValidatingNonce
	}

	cert, err := x509.ParseCertificate(doc.Certificate)
	if err != nil {
		return nil, err
	}

	if err := verifySignature(cert, msg); err != nil {
		log.Errorf("Error verifying signature: %v", err)
		return nil, err
	}

	rootCert := v.rootCert
	if rootCert == nil {
		c, err := GetRootAWSCert()
		if err != nil {
			return nil, err
		}
		rootCert = c
	}

	if err := verifyCertChain(cert, rootCert, doc.Cabundle, v.currentTime); err != nil {
		log.Errorf("Error verifying certificate chain: %v", err)
		return nil, err
	}

	return doc, nil
}

// checksum is found here https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html#validation-process
var rootCertSHA256CheckSum = "8cf60e2b2efca96c6a9e71e851d00c1b6991cc09eadbe64a6a1d1b1eb9faff7c"
var rootCertLocation = "https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip"

func GetRootAWSCert() (*x509.Certificate, error) {
	res, err := http.Get(rootCertLocation)
	if err != nil {
		return nil, err
	}

	zipBy, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	log.Debugf("< Downloaded AWS Root Certificate from %s", rootCertLocation)

	h := sha256.New()
	_, err = h.Write(zipBy)
	if err != nil {
		return nil, err
	}

	checksum := hex.EncodeToString(h.Sum(nil))

	if checksum != rootCertSHA256CheckSum {
		return nil, fmt.Errorf("checksum %s for aws root cert does not match %s", checksum, rootCertSHA256CheckSum)
	}

	log.Debugf("* Verified AWS Root Certificate checksum %s", rootCertSHA256CheckSum)

	r, err := zip.NewReader(bytes.NewReader(zipBy), int64(len(zipBy)))
	if err != nil {
		return nil, err
	}

	file := r.File[0]
	f, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer f.Close()

	pemBytes, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	bl, _ := pem.Decode(pemBytes)

	if bl.Type != "CERTIFICATE" {
		return nil, errors.New("aws root cert not a certificate")
	}

	return x509.ParseCertificate(bl.Bytes)
}

// ParseAttestationDocument is a utility method to return a Attestation Document
// without actually verifying it. Useful for if you need some info out of the
// document but you don't need to verify it.
func ParseAttestationDocument(attestation []byte) (*AttestationDoc, error) {
	msg, err := createSign1(attestation)
	if err != nil {
		return nil, err
	}

	doc := &AttestationDoc{}
	err = cbor.Unmarshal(msg.Payload, doc)
	if err != nil {
		log.Errorf("Error unmarshalling cbor document: %v", err)
		return nil, err
	}

	return doc, nil
}
