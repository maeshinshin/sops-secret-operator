/*
Copyright 2026 maeshinshin.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package decryption

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	sopsv1alpha1 "github.com/maeshinshin/sops-secret-operator/api/v1alpha1"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name        string
		provider    sopsv1alpha1.Provider
		key         []byte
		passphrase  []byte
		wantErr     bool
		wantIsErr   error
		checkResult func(t *testing.T, d Decryptor)
	}{
		{
			name:     "pgp with nil key",
			provider: sopsv1alpha1.ProviderPGP,
			key:      nil,
			wantErr:  true,
		},
		{
			name:     "pgp with empty bytes",
			provider: sopsv1alpha1.ProviderPGP,
			key:      []byte{},
			wantErr:  true,
		},
		{
			name:      "unsupported provider age",
			provider:  sopsv1alpha1.ProviderAge,
			key:       []byte("any"),
			wantErr:   true,
			wantIsErr: ErrUnsupported,
		},
		{
			name:      "unsupported provider kms",
			provider:  sopsv1alpha1.ProviderKMS,
			key:       []byte("any"),
			wantErr:   true,
			wantIsErr: ErrUnsupported,
		},
		{
			name:      "unsupported provider vault",
			provider:  sopsv1alpha1.ProviderVault,
			key:       []byte("any"),
			wantErr:   true,
			wantIsErr: ErrUnsupported,
		},
		{
			name:      "empty provider",
			provider:  "",
			key:       []byte("any"),
			wantErr:   true,
			wantIsErr: ErrUnsupported,
		},
		{
			name:      "unknown provider",
			provider:  sopsv1alpha1.Provider("unknown"),
			key:       []byte("any"),
			wantErr:   true,
			wantIsErr: ErrUnsupported,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := New(tt.provider, tt.key, tt.passphrase)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantIsErr != nil && !errors.Is(err, tt.wantIsErr) {
				t.Errorf("err = %v, wantIsErr %v", err, tt.wantIsErr)
			}
			if tt.checkResult != nil && d != nil {
				tt.checkResult(t, d)
			}
		})
	}
}

func TestErrNoMatch_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *ErrNoMatch
		contains []string
	}{
		{
			name:     "basic",
			err:      &ErrNoMatch{Provider: sopsv1alpha1.ProviderPGP, Reason: "no match"},
			contains: []string{"pgp", "no match"},
		},
		{
			name:     "empty provider",
			err:      &ErrNoMatch{Provider: "", Reason: "r"},
			contains: []string{": r"},
		},
		{
			name:     "empty reason",
			err:      &ErrNoMatch{Provider: sopsv1alpha1.ProviderPGP, Reason: ""},
			contains: []string{"pgp"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := tt.err.Error()
			for _, s := range tt.contains {
				if !contains(msg, s) {
					t.Errorf("Error() = %q, want contains %q", msg, s)
				}
			}
		})
	}
}

func TestErrNoMatch_AsError(t *testing.T) {
	original := &ErrNoMatch{Provider: sopsv1alpha1.ProviderPGP, Reason: "x"}
	wrapped := error(original)

	var got *ErrNoMatch
	if !errors.As(wrapped, &got) {
		t.Fatal("errors.As should match *ErrNoMatch")
	}
	if got.Provider != sopsv1alpha1.ProviderPGP {
		t.Errorf("got provider = %q", got.Provider)
	}
	if got.Reason != "x" {
		t.Errorf("got reason = %q", got.Reason)
	}
}

func TestErrUnsupported_IsError(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{name: "direct", err: ErrUnsupported},
		{name: "wrapped with fmt.Errorf %w", err: fmt.Errorf("context: %w", ErrUnsupported)},
		{name: "wrapped with new provider", err: fmt.Errorf("%w: age", ErrUnsupported)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !errors.Is(tt.err, ErrUnsupported) {
				t.Errorf("errors.Is should match ErrUnsupported for %v", tt.err)
			}
		})
	}
}

func TestNew_ErrorWrapsErrUnsupported(t *testing.T) {
	_, err := New(sopsv1alpha1.ProviderAge, []byte("k"), nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrUnsupported) {
		t.Errorf("errors.Is should match ErrUnsupported, got %v", err)
	}
	if !strings.Contains(err.Error(), "age") {
		t.Errorf("error message should mention provider name 'age', got %q", err.Error())
	}
}

func TestErrUnsupported_AsError(t *testing.T) {
	original := ErrUnsupported
	wrapped := error(original)

	if wrapped.Error() != original.Error() {
		t.Errorf("wrapped = %q, want %q", wrapped.Error(), original.Error())
	}
}

func TestDecrypted_StructFields(t *testing.T) {
	tests := []struct {
		name string
		d    Decrypted
	}{
		{name: "empty", d: Decrypted{}},
		{name: "data only", d: Decrypted{Data: map[string]string{"k": "v"}}},
		{name: "stringData only", d: Decrypted{StringData: map[string]string{"k": "v"}}},
		{name: "both", d: Decrypted{
			Data:       map[string]string{"a": "1"},
			StringData: map[string]string{"b": "2"},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = tt.d.Data
			_ = tt.d.StringData
		})
	}
}

func TestDecryptor_Interface(t *testing.T) {
	tests := []struct {
		name string
		d    Decryptor
	}{
		{name: "nil", d: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var _ Decryptor = tt.d
			_ = context.TODO()
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || indexOf(s, substr) >= 0)
}

func indexOf(s, substr string) int {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
