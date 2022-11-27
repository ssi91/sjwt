package sjwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
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

func (j JWT) GenerateToken(encode bool) (string, error) {
	key := []byte(j.secret) // TODO: encode secret according to `encode` parameter
	if encode {
		encodedKey, err := base64.RawURLEncoding.DecodeString(j.secret)
		if err != nil {
			return "", err
		}
		key = encodedKey
	}
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

func (j JWT) ValidateToken(token string, login string, encoded bool) bool {
	splitToken := strings.Split(token, ".")
	if len(splitToken) != 3 {
		return false
	}

	// header
	var headerBytes = make([]byte, base64.RawURLEncoding.DecodedLen(len(splitToken[0])))
	_, err := base64.RawURLEncoding.Decode(headerBytes, []byte(splitToken[0]))
	if err != nil {
		return false
	}
	var header = &Header{}
	err = json.Unmarshal(headerBytes, header)
	if err != nil {
		return false
	}

	// payload
	var payloadBytes = make([]byte, base64.RawURLEncoding.DecodedLen(len(splitToken[1])))
	_, err = base64.RawURLEncoding.Decode(payloadBytes, []byte(splitToken[1]))
	if err != nil {
		return false
	}
	var payload = &Payload{}
	err = json.Unmarshal(payloadBytes, payload)
	if err != nil {
		return false
	}
	if payload.Name != login {
		return false
	}

	// check signature
	gToken, err := j.GenerateToken(encoded)
	if err != nil {
		return false
	}
	return gToken == token
}
