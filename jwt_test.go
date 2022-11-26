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
