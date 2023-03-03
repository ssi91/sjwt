package sjwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
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

func newHeader(tokenHeader string) (*Header, error) {
	var headerBytes = make([]byte, base64.RawURLEncoding.DecodedLen(len(tokenHeader)))
	_, err := base64.RawURLEncoding.Decode(headerBytes, []byte(tokenHeader))
	if err != nil {
		return nil, err
	}
	var header = &Header{}
	err = json.Unmarshal(headerBytes, header)

	return header, err
}

func newPayload(tokenPayload string) (*Payload, error) {
	var payloadBytes = make([]byte, base64.RawURLEncoding.DecodedLen(len(tokenPayload)))
	_, err := base64.RawURLEncoding.Decode(payloadBytes, []byte(tokenPayload))
	if err != nil {
		return nil, err
	}
	var payload = &Payload{}
	err = json.Unmarshal(payloadBytes, payload)

	return payload, err
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
	key := []byte(j.secret)
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

func checkSignature(tokenHP string, _signature string, secret string) bool {
	mac := hmac.New(sha256.New, []byte(secret))
	_, err := mac.Write([]byte(tokenHP))
	if err != nil {
		return false
	}
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return signature == _signature
}

// ValidateToken FIXME: It doesn't consider signature's encoding
func ValidateToken(token string, secret string) (bool, error) {
	var splitToken []string
	isValid, err := validateToken(&splitToken, token, secret, false)
	return isValid, err
}

func validateToken(splitToken *[]string, token string, secret string, encoded bool) (bool, error) {
	*splitToken = strings.Split(token, ".")
	if len(*splitToken) != 3 {
		return false, errors.New("wrong token format")
	}

	isValid := checkSignature((*splitToken)[0]+"."+(*splitToken)[1], (*splitToken)[2], secret)
	if !isValid {
		return false, errors.New("invalid token signature")
	}

	return true, nil
}

func JWTFromToken(token string, secret string, encoded bool) (*JWT, error) {
	var splitToken []string
	isValid, err := validateToken(&splitToken, token, secret, encoded)
	if !isValid {
		return nil, err
	}

	header, err := newHeader(splitToken[0])
	if err != nil {
		return nil, err
	}

	payload, err := newPayload(splitToken[1])
	if err != nil {
		return nil, err
	}

	return NewJWT(*header, *payload, secret), nil
}
