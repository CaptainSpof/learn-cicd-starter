package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name      string
		headers   http.Header
		wantKey   string
		wantErr   error
		errString string
	}{
		{
			name:    "valid api key",
			headers: http.Header{"Authorization": []string{"ApiKey my-secret-key"}},
			wantKey: "my-secret-key",
		},
		{
			name:    "extra whitespace separated parts are ignored",
			headers: http.Header{"Authorization": []string{"ApiKey my-secret-key trailing"}},
			wantKey: "my-secret-key",
		},
		{
			name:    "nil headers",
			headers: nil,
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:    "no authorization header",
			headers: http.Header{},
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:    "empty authorization header",
			headers: http.Header{"Authorization": []string{""}},
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:      "wrong scheme",
			headers:   http.Header{"Authorization": []string{"Bearer my-secret-key"}},
			errString: "malformed authorization header",
		},
		{
			name:      "scheme is case sensitive",
			headers:   http.Header{"Authorization": []string{"apikey my-secret-key"}},
			errString: "malformed authorization header",
		},
		{
			name:      "scheme without key",
			headers:   http.Header{"Authorization": []string{"ApiKey"}},
			errString: "malformed authorization header",
		},
		{
			name:      "key without scheme",
			headers:   http.Header{"Authorization": []string{"my-secret-key"}},
			errString: "malformed authorization header",
		},
		{
			name:    "scheme with empty key returns empty string and no error",
			headers: http.Header{"Authorization": []string{"ApiKey "}},
			wantKey: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, err := GetAPIKey(tt.headers)

			switch {
			case tt.wantErr != nil:
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("GetAPIKey() error = %v, want %v", err, tt.wantErr)
				}
			case tt.errString != "":
				if err == nil {
					t.Fatalf("GetAPIKey() error = nil, want %q", tt.errString)
				}
				if err.Error() != tt.errString {
					t.Fatalf("GetAPIKey() error = %q, want %q", err.Error(), tt.errString)
				}
			default:
				if err != nil {
					t.Fatalf("GetAPIKey() unexpected error = %v", err)
				}
			}

			if gotKey != tt.wantKey {
				t.Errorf("GetAPIKey() key = %q, want %q", gotKey, tt.wantKey)
			}
		})
	}
}
