package sjwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
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
	header  Header
	payload Payload
	secret  string
}

func NewJWT(header Header, payload Payload, secret string) *JWT {
	return &JWT{
		header:  header,
		payload: payload,
		secret:  secret,
	}
}

func (p Payload) stringify(encode bool) (string, error) {
	payload, err := json.Marshal(p)
	if err != nil {
		// TODO: fall?
	}
	return string(payload), nil
}

func (h Header) stringify(encode bool) (string, error) {
	header, err := json.Marshal(h)
	if err != nil {
		// TODO: fall?
	}
	return string(header), nil
}

func (j JWT) stringifyHeader(encode bool) (string, error) {
	return j.header.stringify(encode)
}

func (j JWT) stringifyPayload(encode bool) (string, error) {
	return j.payload.stringify(encode)
}

func (j JWT) GenerateToken() (string, error) {
	key := []byte(j.secret) // TODO: encode secret according to `encode` parameter
	mac := hmac.New(sha256.New, key)

	payloadStr, err := j.stringifyPayload(false)
	payloadStr = base64.RawURLEncoding.EncodeToString([]byte(payloadStr))
	if err != nil {
		return "", err
	}
	headerStr, err := j.stringifyHeader(false)
	headerStr = base64.RawURLEncoding.EncodeToString([]byte(headerStr))
	if err != nil {
		return "", err
	}
	dataToSign := headerStr + "." + payloadStr
	mac.Write([]byte(dataToSign))

	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	token := dataToSign + "." + signature
	return token, nil
}
