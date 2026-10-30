package auth_test

import (
	"net/http"
	"testing"

	"github.com/bootdotdev/learn-cicd-starter/internal/auth"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name       string
		authHeader string
		wantKey    string
		wantErr    string
	}{
		{
			name:       "valid ApiKey header",
			authHeader: "ApiKey abc123",
			wantKey:    "abc123",
		},
		{
			name:    "missing authorization header",
			wantErr: auth.ErrNoAuthHeaderIncluded.Error(),
		},
		{
			name:       "wrong scheme",
			authHeader: "Bearer abc123",
			wantErr:    "malformed authorization header",
		},
		{
			name:       "missing key",
			authHeader: "ApiKey",
			wantErr:    "malformed authorization header",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			headers := make(http.Header)
			if tc.authHeader != "" {
				headers.Set("Authorization", tc.authHeader)
			}

			gotKey, err := auth.GetAPIKey(headers)
			if tc.wantErr != "" {
				if err == nil || err.Error() != tc.wantErr {
					t.Fatalf("%s: expected error %q, got %v", tc.name, tc.wantErr, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("%s: unexpected error: %v", tc.name, err)
			}

			if gotKey != tc.wantKey {
				t.Fatalf("%s: expected key %q, got %q", tc.name, tc.wantKey, gotKey)
			}
		})
	}
}
