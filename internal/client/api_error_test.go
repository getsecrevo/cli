package client

import (
	"errors"
	"strings"
	"testing"
)

// TestParseAPIErrorEnvelope: a wall response is parsed into a typed *APIError
// whose Error() surfaces the remediation prominently, and whose fields let a
// caller honour retryable:false.
func TestParseAPIErrorEnvelope(t *testing.T) {
	body := []byte(`{"error":"mediated_not_configured","message":"This secret has no mediated-consumption allowlist.","remediation":"A human runs ` + "`secrevo secret proxy-target add`" + `.","retryable":false}`)
	err := parseAPIError(409, body)

	var ae *APIError
	if !errors.As(err, &ae) {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if ae.Status != 409 || ae.Code != "mediated_not_configured" {
		t.Fatalf("status/code = %d/%q", ae.Status, ae.Code)
	}
	if ae.Retryable {
		t.Fatalf("wall must be non-retryable")
	}
	msg := ae.Error()
	if !strings.Contains(msg, "409") || !strings.Contains(msg, "mediated_not_configured") {
		t.Fatalf("Error() must embed status + code (back-compat substring matches): %q", msg)
	}
	if !strings.Contains(msg, "proxy-target add") {
		t.Fatalf("Error() must surface the remediation: %q", msg)
	}
}

// TestParseAPIErrorBackCompat: existing substring checks (status + code) keep
// working — e.g. isForbidden and the not_found_previous grace check.
func TestParseAPIErrorBackCompat(t *testing.T) {
	forbidden := parseAPIError(403, []byte(`{"error":"forbidden","message":"missing required capability"}`))
	if !strings.Contains(forbidden.Error(), "403") || !strings.Contains(forbidden.Error(), "forbidden") {
		t.Fatalf("forbidden must contain 403 + forbidden: %q", forbidden.Error())
	}
	prev := parseAPIError(404, []byte(`{"error":"not_found_previous","message":"grace window expired"}`))
	if !strings.Contains(prev.Error(), "404") || !strings.Contains(prev.Error(), "not_found_previous") {
		t.Fatalf("not_found_previous must contain 404 + code: %q", prev.Error())
	}
}

// TestParseAPIErrorNonEnvelope: a non-envelope body (plain text / empty) still
// yields a usable error that embeds the status and the raw body.
func TestParseAPIErrorNonEnvelope(t *testing.T) {
	plain := parseAPIError(500, []byte("upstream exploded"))
	if !strings.Contains(plain.Error(), "500") || !strings.Contains(plain.Error(), "upstream exploded") {
		t.Fatalf("plain body must embed status + raw: %q", plain.Error())
	}
	empty := parseAPIError(502, nil)
	if !strings.Contains(empty.Error(), "502") {
		t.Fatalf("empty body must still embed status: %q", empty.Error())
	}
}
