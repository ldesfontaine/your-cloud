package controller

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTemporaryHTTPIsModeSpecificStrictAndSourceBounded(t *testing.T) {
	directory := privateTestDirectory(t)
	current := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	if _, err := InitializeAuthority(directory, current); err != nil {
		t.Fatal(err)
	}
	authority, _ := OpenAuthorityStore(directory, current)
	pairing, _ := NewPairingManager(authority)
	pairing.now = func() time.Time { return current }
	sheet, err := pairing.OpenWindow("enrollment")
	if err != nil {
		t.Fatal(err)
	}
	host := controllerServerName(sheet.InfrastructureID) + ":9444"
	handler, err := NewTemporaryHandler(pairing, "enrollment", host, nil)
	if err != nil {
		t.Fatal(err)
	}
	handler.now = func() time.Time { return current }
	requestID := base64.RawURLEncoding.EncodeToString(make([]byte, 16))
	valid := `{"schema_version":1,"window_id":"` + sheet.WindowID + `","window_code":"` + sheet.WindowCode + `","request_id":"` + requestID + `"}`

	wrongRoute := temporaryRequest(handler, host, http.MethodPost, "/v0/recovery/challenge", valid, "192.168.241.193:42000")
	if wrongRoute.Code != http.StatusNotFound {
		t.Fatalf("other window mode route status=%d body=%s", wrongRoute.Code, wrongRoute.Body.String())
	}
	wrongMethod := temporaryRequest(handler, host, http.MethodPut, "/v0/enrollment/challenge", valid, "192.168.241.193:42000")
	if wrongMethod.Code != http.StatusMethodNotAllowed {
		t.Fatalf("wrong method status=%d body=%s", wrongMethod.Code, wrongMethod.Body.String())
	}
	duplicate := strings.Replace(valid, `"schema_version":1`, `"schema_version":1,"schema_version":1`, 1)
	if response := temporaryRequest(handler, host, http.MethodPost, "/v0/enrollment/challenge", duplicate, "192.168.241.193:42000"); response.Code != http.StatusBadRequest {
		t.Fatalf("duplicate JSON status=%d body=%s", response.Code, response.Body.String())
	}
	invalid := strings.Replace(valid, sheet.WindowCode, "AAAAAAAAAAAAAAAAAAAAAAAAAA", 1)
	if response := temporaryRequest(handler, host, http.MethodPost, "/v0/enrollment/challenge", invalid, "192.168.241.200:42000"); response.Code != http.StatusUnauthorized {
		t.Fatalf("first invalid code status=%d body=%s", response.Code, response.Body.String())
	}
	if response := temporaryRequest(handler, host, http.MethodPost, "/v0/enrollment/challenge", invalid, "192.168.241.200:42001"); response.Code != http.StatusTooManyRequests || response.Header().Get("Retry-After") != "1" {
		t.Fatalf("one-per-second source bound status=%d retry=%q", response.Code, response.Header().Get("Retry-After"))
	}
	if response := temporaryRequest(handler, host, http.MethodPost, "/v0/enrollment/challenge", valid, "192.168.241.193:42000"); response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"transaction_id"`) {
		t.Fatalf("valid temporary challenge failed: status=%d body=%s", response.Code, response.Body.String())
	}
}

func temporaryRequest(handler *TemporaryHandler, host, method, path, body, remote string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, "https://"+host+path, strings.NewReader(body))
	request.Host = host
	request.RemoteAddr = remote
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}
