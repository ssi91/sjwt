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
	token, err := jwt.GenerateToken()
	if err != nil {
		t.Errorf("Failed with error: %s", err)
	}
	if token != expectedStr {
		t.Errorf("Token string does not match to expected:\nExpected: %s\nActual: %s\n", expectedStr, token)
	}
}
