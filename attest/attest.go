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
}

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

func verifyCertChain(cert *x509.Certificate, rootCert *x509.Certificate, cabundle [][]byte) error {
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
		CurrentTime:   time.Now().UTC(),
	}

	if _, err := cert.Verify(opts); err != nil {
		return err
	}

	return nil
}

func Attest(attestation []byte, rootCert *x509.Certificate) (*AttestationDoc, error) {
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

	cert, err := x509.ParseCertificate(doc.Certificate)
	if err != nil {
		return nil, err
	}

	if err := verifySignature(cert, msg); err != nil {
		log.Errorf("Error verifying signature: %v", err)
		return nil, err
	}

	if rootCert != nil {
		if err := verifyCertChain(cert, rootCert, doc.Cabundle); err != nil {
			log.Errorf("Error verifying certificate chain: %v", err)
			return nil, err
		}
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
