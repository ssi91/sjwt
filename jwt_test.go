package sjwt

import "testing"

func TestHeader_stringify(t *testing.T) {
	header := Header{
		Alg:  "testAlg",
		Type: "testType",
	}

	str, err := header.stringify(false)
	if err != nil {
		t.Errorf("Failed with error: %s", err)
	}
	expectedStr := "{\"alg\":\"testAlg\",\"type\":\"testType\"}"
	if str != expectedStr {
		t.Errorf("Header string does not match to expected:\nExpected: %s\nActual: %s\n", expectedStr, str)
	}
}

func TestPayload_stringify(t *testing.T) {
	payload := Payload{
		Name: "testName",
	}

	str, err := payload.stringify(false)
	if err != nil {
		t.Errorf("Failed with error: %s", err)
	}
	expectedStr := "{\"name\":\"testName\"}"
	if str != expectedStr {
		t.Errorf("Payload string does not match to expected:\nExpected: %s\nActual: %s\n", expectedStr, str)
	}
}

func TestJWT_GenerateToken(t *testing.T) {
	expectedStr := "eyJhbGciOiJIUzI1NiIsInR5cGUiOiJKV1QifQ.eyJuYW1lIjoiSm9obiBEb2UifQ.2xE9O-ATs4Glk8fmbfu5KTlbvan3CrMEmDperTknU6Q"
	header := Header{
		Alg:  "HS256",
		Type: "JWT",
	}
	payload := Payload{
		Name: "John Doe",
	}
	jwt := NewJWT(header, payload, "your-256-bit-secret")
	token, err := jwt.GenerateToken(false)
	if err != nil {
		t.Errorf("Failed with error: %s", err)
	}
	if token != expectedStr {
		t.Errorf("Token string does not match to expected:\nExpected: %s\nActual: %s\n", expectedStr, token)
	}
}

func TestJWT_GenerateToken_encode(t *testing.T) {
	expectedStr := "eyJhbGciOiJIUzI1NiIsInR5cGUiOiJKV1QifQ.eyJuYW1lIjoiSm9obiBEb2UifQ.78M_nOAoLTZVDh1PM6tzk3mxIrcuaSKMw5PhwIVuAKU"
	header := Header{
		Alg:  "HS256",
		Type: "JWT",
	}
	payload := Payload{
		Name: "John Doe",
	}
	jwt := NewJWT(header, payload, "your-256-bit-secret")
	token, err := jwt.GenerateToken(true)
	if err != nil {
		t.Errorf("Failed with error: %s", err)
	}
	if token != expectedStr {
		t.Errorf("Token string does not match to expected:\nExpected: %s\nActual: %s\n", expectedStr, token)
	}
}

func TestJWT_ValidateToken(t *testing.T) {
	token := "eyJhbGciOiJIUzI1NiIsInR5cGUiOiJKV1QifQ.eyJuYW1lIjoiSm9obiBEb2UifQ.2xE9O-ATs4Glk8fmbfu5KTlbvan3CrMEmDperTknU6Q"
	header := Header{
		Alg:  "HS256",
		Type: "JWT",
	}
	payload := Payload{
		Name: "John Doe",
	}
	jwt := NewJWT(header, payload, "your-256-bit-secret")
	isValid := jwt.ValidateToken(token, "John Doe", false)
	if !isValid {
		t.Errorf("Token string is not valid")
	}
}

func TestJWT_ValidateToken_encoded(t *testing.T) {
	token := "eyJhbGciOiJIUzI1NiIsInR5cGUiOiJKV1QifQ.eyJuYW1lIjoiSm9obiBEb2UifQ.78M_nOAoLTZVDh1PM6tzk3mxIrcuaSKMw5PhwIVuAKU"
	header := Header{
		Alg:  "HS256",
		Type: "JWT",
	}
	payload := Payload{
		Name: "John Doe",
	}
	jwt := NewJWT(header, payload, "your-256-bit-secret")
	isValid := jwt.ValidateToken(token, "John Doe", true)
	if !isValid {
		t.Errorf("Token string is not valid")
	}
}

func TestValidateToken(t *testing.T) {
	token := "eyJhbGciOiJIUzI1NiIsInR5cGUiOiJKV1QifQ.eyJuYW1lIjoiSm9obiBEb2UifQ.2xE9O-ATs4Glk8fmbfu5KTlbvan3CrMEmDperTknU6Q"
	isValid, err := ValidateToken(token, "your-256-bit-secret")

	if !isValid {
		t.Errorf(err.Error())
	}
}
