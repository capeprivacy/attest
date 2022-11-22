package attest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

func TestCreateSign1(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	signer, err := cose.NewSigner(cose.AlgorithmES384, k)
	if err != nil {
		t.Fatal(err)
	}

	msg := cose.NewSign1Message()
	msg.Payload = []byte("hello world")
	msg.Headers.Protected.SetAlgorithm(cose.AlgorithmES384)

	err = msg.Sign(rand.Reader, nil, signer)
	if err != nil {
		t.Fatal(err)
	}

	by, err := msg.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}

	newMsg, err := createSign1(by)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(newMsg.Payload, msg.Payload) {
		t.Fatalf("expected %s got %s", base64.StdEncoding.EncodeToString(newMsg.Payload),
			base64.StdEncoding.EncodeToString(msg.Payload))
	}
}

func TestVerifySig(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	cert := &x509.Certificate{
		PublicKey: &k.PublicKey,
	}

	signer, err := cose.NewSigner(cose.AlgorithmES384, k)
	if err != nil {
		t.Fatal(err)
	}

	msg := cose.NewSign1Message()
	msg.Payload = []byte("hello world")
	msg.Headers.Protected.SetAlgorithm(cose.AlgorithmES384)

	err = msg.Sign(rand.Reader, nil, signer)
	if err != nil {
		t.Fatal(err)
	}

	err = verifySignature(cert, msg)
	if err != nil {
		t.Fatal(err)
	}
}

func createParentCert(t *testing.T, k *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()

	parent := &x509.Certificate{
		IsCA:                  true,
		BasicConstraintsValid: true,
		SubjectKeyId:          []byte{1, 2, 3},
		SerialNumber:          big.NewInt(1234),
		Subject: pkix.Name{
			Country:      []string{"Earth"},
			Organization: []string{"Mother Nature"},
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	parentBy, err := x509.CreateCertificate(rand.Reader, parent, parent, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}

	parentCert, err := x509.ParseCertificate(parentBy)
	if err != nil {
		t.Fatal(err)
	}

	return parentCert
}

func createChildCert(t *testing.T, parent, child *x509.Certificate, k *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()

	childBy, err := x509.CreateCertificate(rand.Reader, child, parent, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}

	childCert, err := x509.ParseCertificate(childBy)
	if err != nil {
		t.Fatal(err)
	}

	return childCert
}

func TestVerifyCertChains(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	parent := createParentCert(t, k)

	intermediate := createChildCert(t, parent, &x509.Certificate{
		IsCA:                  true,
		BasicConstraintsValid: true,
		SubjectKeyId:          []byte{4, 5, 6},
		SerialNumber:          big.NewInt(5678),
		Subject: pkix.Name{
			Country:      []string{"Mars"},
			Organization: []string{"Olympus Mons"},
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}, k)

	cert := createChildCert(t, intermediate, &x509.Certificate{
		IsCA:                  false,
		BasicConstraintsValid: true,
		SubjectKeyId:          []byte{7, 8, 9},
		SerialNumber:          big.NewInt(9101112),
		Subject: pkix.Name{
			Country:      []string{"Jupiter"},
			Organization: []string{"Red"},
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}, k)

	err = verifyCertChain(cert, parent, [][]byte{intermediate.Raw})
	if err != nil {
		t.Fatal(err)
	}
}

func TestAttest(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	parent := createParentCert(t, k)

	intermediate := createChildCert(t, parent, &x509.Certificate{
		IsCA:                  true,
		BasicConstraintsValid: true,
		SubjectKeyId:          []byte{4, 5, 6},
		SerialNumber:          big.NewInt(5678),
		Subject: pkix.Name{
			Country:      []string{"Mars"},
			Organization: []string{"Olympus Mons"},
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}, k)

	cert := createChildCert(t, intermediate, &x509.Certificate{
		IsCA:                  false,
		BasicConstraintsValid: true,
		SubjectKeyId:          []byte{7, 8, 9},
		SerialNumber:          big.NewInt(9101112),
		Subject: pkix.Name{
			Country:      []string{"Jupiter"},
			Organization: []string{"Red"},
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}, k)

	doc := &AttestationDoc{
		ModuleID:    "my-module",
		Timestamp:   uint64(time.Now().Second()),
		Digest:      "abcd",
		PCRs:        map[int][]byte{0: []byte("pcrpcrpcr")},
		Certificate: cert.Raw,
		Cabundle:    [][]byte{intermediate.Raw},
		PublicKey:   []byte("pub key"),
	}

	by, err := cbor.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}

	signer, err := cose.NewSigner(cose.AlgorithmES384, k)
	if err != nil {
		t.Fatal(err)
	}

	msg := cose.NewSign1Message()
	msg.Payload = by
	msg.Headers.Protected.SetAlgorithm(cose.AlgorithmES384)

	err = msg.Sign(rand.Reader, nil, signer)
	if err != nil {
		t.Fatal(err)
	}

	sign1, err := msg.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}

	newDoc, err := Attest(sign1, parent)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(doc, newDoc) {
		t.Fatalf("expected %v got %v", doc, newDoc)
	}
}

func TestGetRootAWSCert(t *testing.T) {
	wantCert, err := os.ReadFile("./testdata/aws_root.pem")
	if err != nil {
		t.Fatal(err)
	}

	bl, _ := pem.Decode(wantCert)

	want, err := x509.ParseCertificate(bl.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := GetRootAWSCert()
	if err != nil {
		t.Fatal(err)
	}

	if !cert.Equal(want) {
		t.Fatal("downloaded cert doesn't match wanted cert")
	}
}
