package management

import (
	"testing"
)

func TestConvertKiroIDETokenToAuthRecord(t *testing.T) {
	data := []byte(`{
		"accessToken":"header.payload.sig",
		"refreshToken":"r1",
		"profileArn":"arn:aws:codewhisperer:us-east-1:1:profile/ABC",
		"expiresAt":"2099-01-01T00:00:00Z",
		"authMethod":"social",
		"provider":"Google"
	}`)

	record, ok, err := convertKiroIDETokenToAuthRecord(data)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !ok {
		t.Fatalf("expected ok=true")
	}
	if record == nil || record.Provider != "kiro" {
		t.Fatalf("unexpected record: %#v", record)
	}
	if record.Metadata == nil || record.Metadata["type"] != "kiro" {
		t.Fatalf("expected metadata type=kiro, got %#v", record.Metadata)
	}
}
