package sjwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

type Header struct {
	Alg  string `json:"alg"`
	Type string `json:"type"`
}

type Payload struct {
	//id   []byte
	Name string `json:"name"`
}

type JWT struct {
	header    Header
	payload   Payload
	signature []byte
}

func (p Payload) stringify(encode bool) (string, error) {
	payload, err := json.Marshal(p)
	if err != nil {
		// TODO: fall?
	}
	// TODO: encode base64 if `encode` == true
	return string(payload), nil
}

func (h Header) stringify(encode bool) (string, error) {
	header, err := json.Marshal(h)
	if err != nil {
		// TODO: fall?
	}
	// TODO: encode base64 if `encode` == true
	return string(header), nil
}

func (j JWT) stringifyHeader(encode bool) (string, error) {
	return j.header.stringify(encode)
}

func (j JWT) stringifyPayload(encode bool) (string, error) {
	return j.payload.stringify(encode)
}

func (j JWT) GenerateToken(login string) (string, error) {
	key := []byte("string") // TODO: pass a secret here
	mac := hmac.New(sha256.New, key)

	j.payload.Name = login
	payloadStr, err := j.stringifyPayload(false) // TODO: encode base64
	if err != nil {
		return "", err
	}
	headerStr, err := j.stringifyHeader(false) // TODO: encode base64
	if err != nil {
		return "", err
	}
	dataToSign := headerStr + "." + payloadStr
	mac.Write([]byte(dataToSign))

	signature := hex.EncodeToString(mac.Sum(nil)) // TODO: encode according to `encode` parameter
	token := dataToSign + "." + signature
	return token, nil
}

func main() {
}
