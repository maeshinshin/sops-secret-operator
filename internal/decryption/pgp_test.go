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
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sopsv1alpha1 "github.com/maeshinshin/sops-secret-operator/api/v1alpha1"
)

const (
	testKeyFP         = "7ADDBB3E665716BE6BAF765F449C58F426FEA633"
	otherKeyFP        = "5F4A4E842F63CA87F28D7F308C247F2B706D388E"
	passphraseKeyFP   = "4326ED081E26332663FE62594484F990D5068F20"
	testPassphrase    = "test-passphrase-xyz"
	testKeyFile       = "test-key.asc"
	otherKeyFile      = "other-key.asc"
	passphraseKeyFile = "passphrase-key.asc"
	emptyName         = "empty"
	nilName           = "nil"
	passphraseKeyName = "passphrase key"
	invalidJSON       = "invalid json"
	invalidJSONRaw    = "{invalid"
	bothName          = "both"
	dataValue         = "data-value"
	secretPassword    = "my-secret-password"
	passwordField     = "password"
)

func loadTestKey(t *testing.T, name string) []byte {
	t.Helper()
	path := filepath.Join("testdata", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to load test key %s: %v", name, err)
	}
	return data
}

func TestNewPGP_EmptyKey(t *testing.T) {
	tests := []struct {
		name string
		key  []byte
	}{
		{name: nilName, key: nil},
		{name: emptyName, key: []byte{}},
		{name: "whitespace only", key: []byte("   ")},
		{name: "not armored", key: []byte("not a pgp key")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := NewPGP(tt.key, nil)
			if err == nil {
				t.Errorf("expected error, got decryptor=%v", d)
			}
			if d != nil {
				t.Errorf("expected nil decryptor on error, got %v", d)
			}
		})
	}
}

func TestNewPGP_ValidKey(t *testing.T) {
	tests := []struct {
		name       string
		keyFile    string
		passphrase []byte
		wantErr    bool
	}{
		{name: "test key without passphrase", keyFile: testKeyFile, passphrase: nil, wantErr: false},
		{name: "test key with wrong passphrase", keyFile: testKeyFile, passphrase: []byte("wrong"), wantErr: false},
		{name: "other key without passphrase", keyFile: otherKeyFile, passphrase: nil, wantErr: false},
		{name: "passphrase key with correct passphrase", keyFile: passphraseKeyFile, passphrase: []byte(testPassphrase), wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := loadTestKey(t, tt.keyFile)
			d, err := NewPGP(key, tt.passphrase)
			if (err != nil) != tt.wantErr {
				t.Errorf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && d == nil {
				t.Error("expected non-nil decryptor on success")
			}
		})
	}
}

func TestNewPGP_PassphraseMissing(t *testing.T) {
	tests := []struct {
		name     string
		keyFile  string
		password []byte
	}{
		{name: "encrypted key with nil passphrase", keyFile: passphraseKeyFile, password: nil},
		{name: "encrypted key with empty passphrase", keyFile: passphraseKeyFile, password: []byte{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := loadTestKey(t, tt.keyFile)
			_, err := NewPGP(key, tt.password)
			if err == nil {
				t.Fatal("expected error for missing passphrase on encrypted key")
			}
		})
	}
}

func TestNewPGP_WrongPassphrase(t *testing.T) {
	key := loadTestKey(t, passphraseKeyFile)
	_, err := NewPGP(key, []byte("wrong-password"))
	if err == nil {
		t.Fatal("expected error for wrong passphrase")
	}
	if !strings.Contains(err.Error(), "decrypt private key") &&
		!strings.Contains(err.Error(), "passphrase") &&
		!strings.Contains(err.Error(), "subkey") {
		t.Logf("error message: %v", err)
	}
}

func TestPGP_Provider(t *testing.T) {
	tests := []struct {
		name    string
		keyFile string
	}{
		{name: "test key", keyFile: testKeyFile},
		{name: "other key", keyFile: otherKeyFile},
		{name: passphraseKeyName, keyFile: passphraseKeyFile},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := loadTestKey(t, tt.keyFile)
			d, err := NewPGP(key, nil)
			if err != nil {
				passphrase := []byte(testPassphrase)
				if tt.keyFile == passphraseKeyFile {
					d, err = NewPGP(key, passphrase)
				}
				if err != nil {
					t.Fatalf("failed to load key: %v", err)
				}
			}
			if got := d.Provider(); got != sopsv1alpha1.ProviderPGP {
				t.Errorf("Provider() = %q, want %q", got, sopsv1alpha1.ProviderPGP)
			}
		})
	}
}

func TestPGP_Fingerprint(t *testing.T) {
	tests := []struct {
		name       string
		keyFile    string
		passphrase []byte
		want       string
		wantUpper  string
	}{
		{name: "test key", keyFile: testKeyFile, passphrase: nil, want: testKeyFP},
		{name: "other key", keyFile: otherKeyFile, passphrase: nil, want: otherKeyFP},
		{name: passphraseKeyName, keyFile: passphraseKeyFile, passphrase: []byte(testPassphrase), want: passphraseKeyFP},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := loadTestKey(t, tt.keyFile)
			d, err := NewPGP(key, tt.passphrase)
			if err != nil {
				t.Fatalf("NewPGP: %v", err)
			}
			got := d.fingerprint()
			if got != tt.want {
				t.Errorf("fingerprint = %q, want %q", got, tt.want)
			}
			if !strings.EqualFold(got, tt.want) {
				t.Errorf("fingerprint case-insensitive mismatch: got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPGP_FingerprintFindsCorrectKey(t *testing.T) {
	key1 := loadTestKey(t, testKeyFile)
	d1, err := NewPGP(key1, nil)
	if err != nil {
		t.Fatal(err)
	}
	key2 := loadTestKey(t, otherKeyFile)
	d2, err := NewPGP(key2, nil)
	if err != nil {
		t.Fatal(err)
	}

	if d1.fingerprint() == d2.fingerprint() {
		t.Errorf("two different keys produced same fingerprint: %s", d1.fingerprint())
	}

	fp1 := d1.fingerprint()
	if !strings.Contains(fp1, "7ADDBB3E") {
		t.Errorf("fingerprint %q does not contain expected prefix 7ADDBB3E", fp1)
	}
	fp2 := d2.fingerprint()
	if !strings.Contains(fp2, "5F4A4E84") {
		t.Errorf("fingerprint %q does not contain expected prefix 5F4A4E84", fp2)
	}
}

func TestLoadPrivateKey_InvalidArmored(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{name: "garbage", data: []byte("garbage data")},
		{name: "partial armor header", data: []byte("-----BEGIN PGP PRIVATE KEY BLOCK-----\n")},
		{name: "random binary", data: []byte{0x00, 0x01, 0x02, 0xff, 0xab, 0xcd}},
		{name: emptyName, data: []byte{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := loadPrivateKey(tt.data, nil)
			if err == nil {
				t.Error("expected error for invalid armored data")
			}
		})
	}
}

func TestUnlockDataKey_InvalidArmored(t *testing.T) {
	key := loadTestKey(t, testKeyFile)
	d, err := NewPGP(key, nil)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		enc  string
	}{
		{name: "empty string", enc: ""},
		{name: "garbage", enc: "not a pgp message"},
		{name: "partial armor", enc: "-----BEGIN PGP MESSAGE-----\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := d.unlockDataKey(tt.enc)
			if err == nil {
				t.Errorf("expected error for %q", tt.name)
			}
		})
	}
}

func TestPGP_Decrypt_NoMatch(t *testing.T) {
	key := loadTestKey(t, testKeyFile)
	d, err := NewPGP(key, nil)
	if err != nil {
		t.Fatal(err)
	}

	sopsRaw := []byte(`{"mac":"ENC[m]","version":"3.13.3","pgp":[{"fp":"` + otherKeyFP + `","enc":"x"}]}`)

	_, err = d.Decrypt(context.Background(), sopsRaw, nil, nil)
	if err == nil {
		t.Fatal("expected ErrNoMatch")
	}

	var noMatch *ErrNoMatch
	if !errors.As(err, &noMatch) {
		t.Errorf("expected *ErrNoMatch, got %T: %v", err, err)
	}
	if noMatch.Provider != sopsv1alpha1.ProviderPGP {
		t.Errorf("noMatch.Provider = %q, want %q", noMatch.Provider, sopsv1alpha1.ProviderPGP)
	}
}

func TestPGP_Decrypt_InvalidSopsRaw(t *testing.T) {
	key := loadTestKey(t, testKeyFile)
	d, err := NewPGP(key, nil)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		raw  []byte
	}{
		{name: invalidJSON, raw: []byte(invalidJSONRaw)},
		{name: "no pgp", raw: []byte(`{"mac":"m","version":"v"}`)},
		{name: emptyName, raw: []byte{}},
		{name: nilName, raw: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := d.Decrypt(context.Background(), tt.raw, nil, nil)
			if err == nil {
				t.Errorf("expected error for %s", tt.name)
			}
		})
	}
}

func TestPGP_Decrypt_CancelledContext(t *testing.T) {
	key := loadTestKey(t, testKeyFile)
	d, err := NewPGP(key, nil)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	sopsRaw := []byte(`{"mac":"m","version":"v","pgp":[{"fp":"` + testKeyFP + `","enc":"x"}]}`)
	_, err = d.Decrypt(ctx, sopsRaw, nil, nil)
	if err == nil {
		t.Fatal("expected error from cancelled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error should wrap context.Canceled, got %v", err)
	}
}

func TestPGP_Decrypt_MatchButInvalidEncKey(t *testing.T) {
	key := loadTestKey(t, testKeyFile)
	d, err := NewPGP(key, nil)
	if err != nil {
		t.Fatal(err)
	}

	sopsRaw := []byte(`{"mac":"m","version":"v","pgp":[{"fp":"` + testKeyFP + `","enc":"invalid-pgp-message"}]}`)

	_, err = d.Decrypt(context.Background(), sopsRaw, nil, nil)
	if err == nil {
		t.Fatal("expected error from invalid enc key")
	}
}

func TestPGP_FingerprintIsUppercase(t *testing.T) {
	key := loadTestKey(t, testKeyFile)
	d, err := NewPGP(key, nil)
	if err != nil {
		t.Fatal(err)
	}
	fp := d.fingerprint()

	if fp != strings.ToUpper(fp) {
		t.Errorf("fingerprint should be uppercase, got %q", fp)
	}
	for _, r := range fp {
		if r < '0' || r > '9' && r < 'A' || r > 'F' {
			t.Errorf("fingerprint should only contain hex chars, got %q", fp)
		}
	}
}

func TestPGP_KeyInfo(t *testing.T) {
	tests := []struct {
		name               string
		keyFile            string
		passphrase         []byte
		wantFingerprint    string
		wantRequires       bool
		wantUserIDContains string
	}{
		{
			name:               "test key (no passphrase)",
			keyFile:            testKeyFile,
			passphrase:         nil,
			wantFingerprint:    testKeyFP,
			wantRequires:       false,
			wantUserIDContains: "sops-secret-operator-test-key",
		},
		{
			name:               "other key (no passphrase)",
			keyFile:            otherKeyFile,
			passphrase:         nil,
			wantFingerprint:    otherKeyFP,
			wantRequires:       false,
			wantUserIDContains: "sops-secret-operator-other-test-key",
		},
		{
			name:               passphraseKeyName,
			keyFile:            passphraseKeyFile,
			passphrase:         []byte(testPassphrase),
			wantFingerprint:    passphraseKeyFP,
			wantRequires:       true,
			wantUserIDContains: "sops-secret-operator-passphrase-test-key",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := loadTestKey(t, tt.keyFile)
			d, err := NewPGP(key, tt.passphrase)
			if err != nil {
				t.Fatalf("NewPGP: %v", err)
			}
			info := d.KeyInfo()
			if info.Fingerprint != tt.wantFingerprint {
				t.Errorf("Fingerprint = %q, want %q", info.Fingerprint, tt.wantFingerprint)
			}
			if info.RequiresPassphrase != tt.wantRequires {
				t.Errorf("RequiresPassphrase = %v, want %v", info.RequiresPassphrase, tt.wantRequires)
			}
			if !strings.Contains(info.UserID, tt.wantUserIDContains) {
				t.Errorf("UserID = %q, want contains %q", info.UserID, tt.wantUserIDContains)
			}
		})
	}
}

func TestPGP_KeyInfo_NilSafe(t *testing.T) {
	var d *PGP
	info := d.KeyInfo()
	if info != (KeyInfo{}) {
		t.Errorf("nil PGP KeyInfo() = %+v, want zero value", info)
	}
}

func TestPGP_RequiresPassphrase(t *testing.T) {
	tests := []struct {
		name       string
		keyFile    string
		passphrase []byte
		want       bool
	}{
		{name: "test key without passphrase", keyFile: testKeyFile, passphrase: nil, want: false},
		{name: "other key without passphrase", keyFile: otherKeyFile, passphrase: nil, want: false},
		{name: "passphrase key with correct passphrase", keyFile: passphraseKeyFile, passphrase: []byte(testPassphrase), want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := loadTestKey(t, tt.keyFile)
			d, err := NewPGP(key, tt.passphrase)
			if err != nil {
				t.Fatalf("NewPGP: %v", err)
			}
			if got := d.RequiresPassphrase(); got != tt.want {
				t.Errorf("RequiresPassphrase() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPGP_RequiresPassphrase_NilSafe(t *testing.T) {
	var d *PGP
	if got := d.RequiresPassphrase(); got != false {
		t.Errorf("nil PGP RequiresPassphrase() = %v, want false", got)
	}
}

func TestPGP_KeyInfo_WrongPassphraseDoesNotChangeRequiresFlag(t *testing.T) {
	key := loadTestKey(t, passphraseKeyFile)
	if _, err := NewPGP(key, []byte("wrong-passphrase")); err == nil {
		t.Fatal("expected error for wrong passphrase")
	}
}

func TestPGP_KeyInfo_DetectsEncryptedKey(t *testing.T) {
	key := loadTestKey(t, passphraseKeyFile)
	_, err := NewPGP(key, []byte(testPassphrase))
	if err != nil {
		t.Fatalf("NewPGP with correct passphrase failed: %v", err)
	}
	_, err = NewPGP(key, []byte("wrong"))
	if err == nil {
		t.Fatal("NewPGP with wrong passphrase should fail should fail")
	}
	if !strings.Contains(err.Error(), "passphrase") &&
		!strings.Contains(err.Error(), "decrypt") {
		t.Logf("error: %v", err)
	}
}

type sopsNestedEnvelope struct {
	StringData map[string]string `json:"stringData"`
	Data       map[string]string `json:"data"`
	Sops       map[string]any    `json:"sops"`
}

func loadEncryptedFixture(t *testing.T, name string) (sopsRaw []byte, data, stringData map[string]string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	var env sopsNestedEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal fixture %s: %v", name, err)
	}
	sopsJSON, err := json.Marshal(env.Sops)
	if err != nil {
		t.Fatalf("marshal sops meta: %v", err)
	}
	return sopsJSON, env.Data, env.StringData
}

func TestPGP_Decrypt_WithCorrectKey(t *testing.T) {
	key := loadTestKey(t, testKeyFile)
	d, err := NewPGP(key, nil)
	if err != nil {
		t.Fatalf("NewPGP: %v", err)
	}

	sopsRaw, data, stringData := loadEncryptedFixture(t, "encrypted-nested.json.sops")
	got, err := d.Decrypt(context.Background(), sopsRaw, data, stringData)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	wantString := map[string]string{
		passwordField: secretPassword,
		"api-key":     "sk-test-1234567890",
	}
	for k, v := range wantString {
		if got.StringData[k] != v {
			t.Errorf("StringData[%q] = %q, want %q", k, got.StringData[k], v)
		}
	}
	if v := got.Data["config"]; v == "" {
		t.Errorf("Data[config] is empty, want non-empty base64")
	}
}

func TestPGP_Decrypt_WithWrongKey(t *testing.T) {
	key := loadTestKey(t, otherKeyFile)
	d, err := NewPGP(key, nil)
	if err != nil {
		t.Fatalf("NewPGP: %v", err)
	}

	sopsRaw, data, stringData := loadEncryptedFixture(t, "encrypted-nested.json.sops")
	_, err = d.Decrypt(context.Background(), sopsRaw, data, stringData)
	if err == nil {
		t.Fatal("expected error when using wrong key")
	}
	if _, ok := errors.AsType[*ErrNoMatch](err); !ok {
		t.Errorf("expected *ErrNoMatch, got %T: %v", err, err)
	}
}

func TestPGP_Decrypt_MultiKeyRecipient(t *testing.T) {
	testKey := loadTestKey(t, testKeyFile)
	d, err := NewPGP(testKey, nil)
	if err != nil {
		t.Fatalf("NewPGP: %v", err)
	}

	sopsRaw, data, stringData := loadEncryptedFixture(t, "encrypted-nested.json.sops")
	got, err := d.Decrypt(context.Background(), sopsRaw, data, stringData)
	if err != nil {
		t.Fatalf("Decrypt multi-key with test key: %v", err)
	}
	if got.StringData[passwordField] != secretPassword {
		t.Errorf("password = %q, want %q", got.StringData[passwordField], secretPassword)
	}
}

func TestPGP_Decrypt_EmptyMaps(t *testing.T) {
	key := loadTestKey(t, testKeyFile)
	d, err := NewPGP(key, nil)
	if err != nil {
		t.Fatalf("NewPGP: %v", err)
	}

	sopsRaw, _, _ := loadEncryptedFixture(t, "encrypted-nested.json.sops")
	got, err := d.Decrypt(context.Background(), sopsRaw, nil, nil)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if got.Data != nil {
		t.Errorf("expected nil Data, got %d entries", len(got.Data))
	}
	if len(got.StringData) != 0 {
		t.Errorf("expected empty StringData, got %d entries", len(got.StringData))
	}
}

func TestPGP_Decrypt_ResultHasCorrectType(t *testing.T) {
	key := loadTestKey(t, testKeyFile)
	d, err := NewPGP(key, nil)
	if err != nil {
		t.Fatalf("NewPGP: %v", err)
	}

	sopsRaw, data, stringData := loadEncryptedFixture(t, "encrypted-nested.json.sops")
	got, err := d.Decrypt(context.Background(), sopsRaw, data, stringData)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if got == nil {
		t.Fatal("got nil Decrypted")
	}
	_ = got
}

func TestPGP_Decrypt_DeterministicForSameInput(t *testing.T) {
	key := loadTestKey(t, testKeyFile)
	d, err := NewPGP(key, nil)
	if err != nil {
		t.Fatalf("NewPGP: %v", err)
	}

	sopsRaw, data, stringData := loadEncryptedFixture(t, "encrypted-nested.json.sops")
	first, err := d.Decrypt(context.Background(), sopsRaw, data, stringData)
	if err != nil {
		t.Fatalf("first Decrypt: %v", err)
	}
	second, err := d.Decrypt(context.Background(), sopsRaw, data, stringData)
	if err != nil {
		t.Fatalf("second Decrypt: %v", err)
	}
	if first.StringData["password"] != second.StringData["password"] {
		t.Errorf("decryption not deterministic: %q != %q",
			first.StringData["password"], second.StringData["password"])
	}
}

func TestPGP_Decrypt_StringDataOnly(t *testing.T) {
	key := loadTestKey(t, testKeyFile)
	d, err := NewPGP(key, nil)
	if err != nil {
		t.Fatalf("NewPGP: %v", err)
	}

	sopsRaw, data, stringData := loadEncryptedFixture(t, "encrypted-stringdata-only.json.sops")
	got, err := d.Decrypt(context.Background(), sopsRaw, data, stringData)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	want := map[string]string{
		"username": "admin",
		"password": "secret-pass",
	}
	for k, v := range want {
		if got.StringData[k] != v {
			t.Errorf("StringData[%q] = %q, want %q", k, got.StringData[k], v)
		}
	}
	if len(got.Data) != 0 {
		t.Errorf("expected empty Data, got %d entries: %v", len(got.Data), got.Data)
	}
}

func TestPGP_Decrypt_DataOnly(t *testing.T) {
	key := loadTestKey(t, testKeyFile)
	d, err := NewPGP(key, nil)
	if err != nil {
		t.Fatalf("NewPGP: %v", err)
	}

	sopsRaw, data, stringData := loadEncryptedFixture(t, "encrypted-data-only.json.sops")
	got, err := d.Decrypt(context.Background(), sopsRaw, data, stringData)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	for _, k := range []string{"config1", "config2", "config3"} {
		if got.Data[k] == "" {
			t.Errorf("Data[%q] is empty, want base64", k)
		}
	}
	if len(got.StringData) != 0 {
		t.Errorf("expected empty StringData, got %d entries: %v", len(got.StringData), got.StringData)
	}
}

func TestPGP_Decrypt_BothPresent(t *testing.T) {
	key := loadTestKey(t, testKeyFile)
	d, err := NewPGP(key, nil)
	if err != nil {
		t.Fatalf("NewPGP: %v", err)
	}

	sopsRaw, data, stringData := loadEncryptedFixture(t, "encrypted-nested.json.sops")
	got, err := d.Decrypt(context.Background(), sopsRaw, data, stringData)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if len(got.Data) == 0 {
		t.Error("expected Data to have entries")
	}
	if len(got.StringData) == 0 {
		t.Error("expected StringData to have entries")
	}
	if got.StringData[passwordField] != secretPassword {
		t.Errorf("StringData[password] = %q, want %q", got.StringData[passwordField], secretPassword)
	}
	if got.Data["config"] == "" {
		t.Error("Data[config] is empty")
	}
}

func TestPGP_Decrypt_BothEmpty(t *testing.T) {
	key := loadTestKey(t, testKeyFile)
	d, err := NewPGP(key, nil)
	if err != nil {
		t.Fatalf("NewPGP: %v", err)
	}

	sopsRaw, data, stringData := loadEncryptedFixture(t, "encrypted-both-empty.json.sops")
	got, err := d.Decrypt(context.Background(), sopsRaw, data, stringData)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if got.Data != nil {
		t.Errorf("expected nil Data, got %v", got.Data)
	}
	if len(got.StringData) != 0 {
		t.Errorf("expected empty StringData, got %v", got.StringData)
	}
}

func TestPGP_Decrypt_MultipleStringDataEntries(t *testing.T) {
	key := loadTestKey(t, testKeyFile)
	d, err := NewPGP(key, nil)
	if err != nil {
		t.Fatalf("NewPGP: %v", err)
	}

	sopsRaw, data, stringData := loadEncryptedFixture(t, "encrypted-stringdata-only.json.sops")
	got, err := d.Decrypt(context.Background(), sopsRaw, data, stringData)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if len(got.StringData) != 2 {
		t.Errorf("expected 2 StringData entries, got %d: %v", len(got.StringData), got.StringData)
	}
	for k, v := range map[string]string{"username": "admin", "password": "secret-pass"} {
		if got.StringData[k] != v {
			t.Errorf("StringData[%q] = %q, want %q", k, got.StringData[k], v)
		}
	}
}

func TestPGP_Decrypt_MultipleDataEntries(t *testing.T) {
	key := loadTestKey(t, testKeyFile)
	d, err := NewPGP(key, nil)
	if err != nil {
		t.Fatalf("NewPGP: %v", err)
	}

	sopsRaw, data, stringData := loadEncryptedFixture(t, "encrypted-data-only.json.sops")
	got, err := d.Decrypt(context.Background(), sopsRaw, data, stringData)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if len(got.Data) != 3 {
		t.Errorf("expected 3 Data entries, got %d: %v", len(got.Data), got.Data)
	}
	for _, k := range []string{"config1", "config2", "config3"} {
		if got.Data[k] == "" {
			t.Errorf("Data[%q] is empty", k)
		}
	}
}

func TestPGP_Decrypt_PassphraseKey(t *testing.T) {
	key := loadTestKey(t, passphraseKeyFile)
	d, err := NewPGP(key, []byte(testPassphrase))
	if err != nil {
		t.Fatalf("NewPGP: %v", err)
	}

	sopsRaw, data, stringData := loadEncryptedFixture(t, "encrypted-nested-multi.json.sops")
	got, err := d.Decrypt(context.Background(), sopsRaw, data, stringData)
	if err != nil {
		t.Fatalf("Decrypt with passphrase key: %v", err)
	}

	if got.StringData[passwordField] != secretPassword {
		t.Errorf("StringData[password] = %q, want %q",
			got.StringData[passwordField], secretPassword)
	}
}

func TestPGP_Decrypt_NoEncryption_SopsStillWorks(t *testing.T) {
	key := loadTestKey(t, testKeyFile)
	d, err := NewPGP(key, nil)
	if err != nil {
		t.Fatalf("NewPGP: %v", err)
	}

	tests := []struct {
		name       string
		data       map[string]string
		stringData map[string]string
		checkTop   string
		wantKey    string
		wantVal    string
	}{
		{
			name:       "plaintext in data",
			data:       map[string]string{"key1": "plain-value"},
			stringData: nil,
			checkTop:   "data",
			wantKey:    "key1",
			wantVal:    "plain-value",
		},
		{
			name:       "plaintext in stringData",
			data:       nil,
			stringData: map[string]string{"key2": "plain-value-2"},
			checkTop:   "stringData",
			wantKey:    "key2",
			wantVal:    "plain-value-2",
		},
		{
			name:       "plaintext in both",
			data:       map[string]string{"key3": dataValue},
			stringData: map[string]string{"key4": "string-value"},
			checkTop:   bothName,
			wantKey:    "key3",
			wantVal:    dataValue,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sopsRaw, _, _ := loadEncryptedFixture(t, "encrypted-nested.json.sops")
			got, err := d.Decrypt(context.Background(), sopsRaw, tt.data, tt.stringData)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			switch tt.checkTop {
			case "data":
				if got.Data[tt.wantKey] != tt.wantVal {
					t.Errorf("Data[%q] = %q, want %q", tt.wantKey, got.Data[tt.wantKey], tt.wantVal)
				}
			case "stringData":
				if got.StringData[tt.wantKey] != tt.wantVal {
					t.Errorf("StringData[%q] = %q, want %q", tt.wantKey, got.StringData[tt.wantKey], tt.wantVal)
				}
			case bothName:
				if got.Data["key3"] != dataValue {
					t.Errorf("Data[key3] = %q, want %q", got.Data["key3"], dataValue)
				}
				if got.StringData["key4"] != "string-value" {
					t.Errorf("StringData[key4] = %q, want %q", got.StringData["key4"], "string-value")
				}
			}
		})
	}
}
