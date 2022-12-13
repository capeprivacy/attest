//go:build !nonsm

package attest

import (
	"errors"

	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
	"github.com/hf/nsm/response"
)

type Manager struct {
	PublicKey []byte
}

func (m Manager) GetAttestationDocument(nonce []byte, userData []byte) ([]byte, error) {
	return GetAttestationDoc(m.PublicKey, nonce, userData)
}

func (m Manager) GetAttestationDocWithPublicKey(pk []byte, nonce []byte, userData []byte) ([]byte, error) {
	return GetAttestationDoc(pk, nonce, userData)
}

type NSM interface {
	Send(req request.Request) (response.Response, error)
}

func openDefaultSession() (NSM, error) {
	return nsm.OpenDefaultSession()
}

func GetAttestationDoc(publicKey []byte, nonce []byte, userData []byte) ([]byte, error) {
	sess, err := openSession()
	if err != nil {
		return nil, err
	}

	res, err := sess.Send(&request.Attestation{
		UserData:  userData,
		Nonce:     nonce,
		PublicKey: publicKey,
	})
	if err != nil {
		return nil, err
	}

	if res.Error != "" {
		return nil, errors.New(string(res.Error))
	}

	if res.Attestation == nil || res.Attestation.Document == nil {
		return nil, errors.New("NSM device did not return an attestation")
	}

	return res.Attestation.Document, nil
}

var openSession = openDefaultSession
