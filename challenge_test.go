package goethauth

import (
	"testing"
)

func Test_GetChallenge(t *testing.T) {
	tests := []struct {
		name    string
		wantLen int64
		wantErr bool
	}{
		{
			name:    "Normal challenge",
			wantLen: 64,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetChallenge()
			if (err != nil) != tt.wantErr {
				t.Errorf("got unexpected error: %v", err)
			}
			if len(got) != 64 {
				t.Errorf("got unexpected challenge length: %d", len(got))
			}
		})
	}
}
