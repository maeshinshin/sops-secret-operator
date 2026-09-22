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
	"encoding/json"
	"testing"
	"time"
)

const (
	emptySopsName       = "empty"
	abcdSopsName        = "ABCD1234"
	passphraseSopsFP    = "4326ED081E26332663FE62594484F990D5068F20"
	aaaaSopsFP          = "AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111"
	anySopsFP           = "ANY"
	invalidJSONSopsName = "invalid json"
	encAaa              = "enc-aaa"
)

func TestNormalizeFP(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: emptySopsName, in: "", want: ""},
		{name: "no whitespace", in: abcdSopsName, want: abcdSopsName},
		{name: "lowercase", in: "abcd1234", want: abcdSopsName},
		{name: "mixed case", in: "AbCd1234", want: abcdSopsName},
		{name: "single space", in: "AB CD1234", want: abcdSopsName},
		{name: "multiple spaces", in: "A B C D 1 2 3 4", want: abcdSopsName},
		{name: "leading space", in: " ABCD1234", want: abcdSopsName},
		{name: "trailing space", in: "ABCD1234 ", want: abcdSopsName},
		{name: "tab and newline", in: "AB\tCD\n1234", want: abcdSopsName},
		{name: "full fingerprint formatted", in: passphraseSopsFP, want: passphraseSopsFP},
		{name: "full fingerprint with spaces", in: "4326 ED08 1E26 3326 63FE 6259 4484 F990 D506 8F20", want: passphraseSopsFP},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeFP(tt.in); got != tt.want {
				t.Errorf("normalizeFP(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestFindPGPRecipient(t *testing.T) {
	meta := &MetaWithPGP{
		Meta: Meta{MAC: "mac", Version: "3.13.3"},
		PGP: []PGPRecipient{
			{CreatedAt: time.Now(), Enc: encAaa, FP: aaaaSopsFP},
			{CreatedAt: time.Now(), Enc: "enc-bbb", FP: "BBBB2222BBBB2222BBBB2222BBBB2222BBBB2222"},
			{CreatedAt: time.Now(), Enc: "enc-ccc", FP: "CCCC3333CCCC3333CCCC3333CCCC3333CCCC3333"},
		},
	}

	tests := []struct {
		name        string
		fingerprint string
		want        string
	}{
		{name: "exact match first", fingerprint: aaaaSopsFP, want: encAaa},
		{name: "exact match middle", fingerprint: "BBBB2222BBBB2222BBBB2222BBBB2222BBBB2222", want: "enc-bbb"},
		{name: "exact match last", fingerprint: "CCCC3333CCCC3333CCCC3333CCCC3333CCCC3333", want: "enc-ccc"},
		{name: "lowercase match", fingerprint: "aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111", want: encAaa},
		{name: "uppercase match", fingerprint: aaaaSopsFP, want: encAaa},
		{name: "with spaces match", fingerprint: "AAAA 1111 AAAA 1111 AAAA 1111 AAAA 1111 AAAA 1111", want: encAaa},
		{name: "mixed case and spaces", fingerprint: "aaaa 1111 aaaa 1111 aaaa 1111 aaaa 1111 aaaa 1111", want: encAaa},
		{name: "not found", fingerprint: "DDDD4444DDDD4444DDDD4444DDDD4444DDDD4444", want: ""},
		{name: "empty fingerprint", fingerprint: "", want: ""},
		{name: "partial match", fingerprint: "AAAA1111", want: ""},
		{name: "case insensitive partial", fingerprint: "aaaa1111", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := meta.FindPGPRecipient(tt.fingerprint); got != tt.want {
				t.Errorf("FindPGPRecipient(%q) = %q, want %q", tt.fingerprint, got, tt.want)
			}
		})
	}
}

func TestFindPGPRecipient_EmptyMeta(t *testing.T) {
	tests := []struct {
		name string
		meta *MetaWithPGP
		fp   string
		want string
	}{
		{name: "nil meta", meta: nil, fp: anySopsFP, want: ""},
		{name: "empty pgp list", meta: &MetaWithPGP{}, fp: anySopsFP, want: ""},
		{name: "nil pgp slice", meta: &MetaWithPGP{PGP: nil}, fp: anySopsFP, want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.meta.FindPGPRecipient(tt.fp); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseMeta(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantErr bool
		check   func(t *testing.T, m *Meta)
	}{
		{
			name: "valid",
			raw:  `{"lastmodified": "2026-09-08T15:33:32Z", "mac": "ENC[x]", "version": "3.13.3"}`,
			check: func(t *testing.T, m *Meta) {
				if m.Version != "3.13.3" {
					t.Errorf("version = %q", m.Version)
				}
				if m.MAC != "ENC[x]" {
					t.Errorf("mac = %q", m.MAC)
				}
				if m.LastModified.IsZero() {
					t.Error("lastmodified not parsed")
				}
			},
		},
		{
			name: "valid with encrypted_regex",
			raw:  `{"encrypted_regex": "^(data|stringData)$", "lastmodified": "2026-09-08T15:33:32Z", "mac": "m", "version": "v"}`,
			check: func(t *testing.T, m *Meta) {
				if m.EncryptedRegex != "^(data|stringData)$" {
					t.Errorf("encrypted_regex = %q", m.EncryptedRegex)
				}
			},
		},
		{
			name:    invalidJSONSopsName,
			raw:     `{invalid}`,
			wantErr: true,
		},
		{
			name:    emptySopsName,
			raw:     ``,
			wantErr: true,
		},
		{
			name:    "wrong type",
			raw:     `{"mac": 123}`,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseMeta([]byte(tt.raw))
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.check != nil && got != nil {
				tt.check(t, got)
			}
		})
	}
}

func TestParseMetaWithPGP(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantErr bool
		check   func(t *testing.T, m *MetaWithPGP)
	}{
		{
			name: "with single pgp",
			raw:  `{"mac": "m", "version": "v", "pgp": [{"fp": "AAAA", "enc": "e"}]}`,
			check: func(t *testing.T, m *MetaWithPGP) {
				if len(m.PGP) != 1 {
					t.Errorf("pgp len = %d", len(m.PGP))
				}
				if m.PGP[0].FP != "AAAA" {
					t.Errorf("fp = %q", m.PGP[0].FP)
				}
			},
		},
		{
			name: "with multiple pgp",
			raw:  `{"mac": "m", "version": "v", "pgp": [{"fp": "A", "enc": "a"}, {"fp": "B", "enc": "b"}]}`,
			check: func(t *testing.T, m *MetaWithPGP) {
				if len(m.PGP) != 2 {
					t.Errorf("pgp len = %d", len(m.PGP))
				}
			},
		},
		{
			name:    "no pgp field",
			raw:     `{"mac": "m", "version": "v"}`,
			wantErr: true,
		},
		{
			name:    "empty pgp array",
			raw:     `{"mac": "m", "version": "v", "pgp": []}`,
			wantErr: true,
		},
		{
			name:    invalidJSONSopsName,
			raw:     `{broken`,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseMetaWithPGP([]byte(tt.raw))
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.check != nil && got != nil {
				tt.check(t, got)
			}
		})
	}
}

func TestMeta_JSONRoundtrip(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{name: "single pgp", raw: `{"lastmodified":"2026-09-08T15:33:32Z","mac":"m","version":"v","pgp":[{"fp":"A","enc":"e"}]}`},
		{name: "multiple pgp", raw: `{"lastmodified":"2026-09-08T15:33:32Z","mac":"m","version":"v","pgp":[{"fp":"A","enc":"a"},{"fp":"B","enc":"b"},{"fp":"C","enc":"c"}]}`},
		{name: "full fingerprint pgp", raw: `{"lastmodified":"2026-09-08T15:33:32Z","mac":"ENC[AES256_GCM,data:x,iv:y,tag:z,type:str]","version":"3.13.3","pgp":[{"created_at":"2026-09-08T15:33:32Z","fp":"` + passphraseSopsFP + `","enc":"-----BEGIN PGP MESSAGE-----\n-----END PGP MESSAGE-----"}]}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			meta, err := ParseMetaWithPGP([]byte(tt.raw))
			if err != nil {
				t.Fatal(err)
			}
			out, err := json.Marshal(meta)
			if err != nil {
				t.Fatal(err)
			}
			again, err := ParseMetaWithPGP(out)
			if err != nil {
				t.Fatalf("roundtrip failed: %s\noriginal: %s\nmarshaled: %s", err, tt.raw, out)
			}
			if len(again.PGP) != len(meta.PGP) {
				t.Errorf("pgp count mismatch: %d != %d", len(again.PGP), len(meta.PGP))
			}
			for i := range meta.PGP {
				if again.PGP[i].FP != meta.PGP[i].FP {
					t.Errorf("pgp[%d].FP = %q, want %q", i, again.PGP[i].FP, meta.PGP[i].FP)
				}
				if again.PGP[i].Enc != meta.PGP[i].Enc {
					t.Errorf("pgp[%d].Enc = %q, want %q", i, again.PGP[i].Enc, meta.PGP[i].Enc)
				}
			}
		})
	}
}
