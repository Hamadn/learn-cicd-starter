package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetApiKey(t *testing.T) {
	type test struct {
		name    string
		header  http.Header
		want    string
		wantErr error
	}

	var ErrMalformedAuthorizationHeader = errors.New("malformed authorization header")

	tests := []test{
		{name: "Missing header", header: http.Header{}, want: "", wantErr: ErrNoAuthHeaderIncluded},
		{name: "Empty header", header: http.Header{"Authorization": []string{""}}, want: "", wantErr: ErrNoAuthHeaderIncluded},
		{name: "Valid key", header: http.Header{"Authorization": []string{"ApiKey abc123"}}, want: "abc123", wantErr: nil},
		{name: "Wrong prefix", header: http.Header{"Authorization": []string{"Bearer token"}}, want: "", wantErr: ErrMalformedAuthorizationHeader},
		{name: "No space", header: http.Header{"Authorization": []string{"ApiKey"}}, want: "", wantErr: ErrMalformedAuthorizationHeader},
		{name: "Extra spaces", header: http.Header{"Authorization": []string{"ApiKey  abc123"}}, want: "", wantErr: nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotKey, gotErr := GetAPIKey(tc.header)
			if gotKey != tc.want {
				t.Fatalf("%s: key: expected %q, got %q", tc.name, tc.want, gotKey)
			}
			if tc.wantErr == nil || gotErr == nil {
				if gotErr == tc.wantErr {
					t.Fatalf("%s: err: expected %v, got %v", tc.name, tc.wantErr, gotErr)
				}
			} else if gotErr.Error() != tc.wantErr.Error() {
				t.Fatalf("%s: err: expected %v, got %v", tc.name, tc.wantErr, gotErr)
			}
		})
	}
}
