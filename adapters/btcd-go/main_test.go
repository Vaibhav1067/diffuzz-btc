package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// Mainnet tx aca326a7... spending a P2PKH output (same pair as the Core adapter's tests).
const (
	spending = "02000000013f7cebd65c27431a90bba7f796914fe8cc2ddfc3f2cbd6f7e5f2fc854534da95000000006b483045022100de1ac3bcdfb0332207c4a91f3832bd2c2915840165f876ab47c5f8996b971c3602201c6c053d750fadde599e6f5c4e1963df0f01fc0d97815e8157e3d59fe09ca30d012103699b464d1d8bc9e47d4fb1cdaa89a1c5783d68363c4dbc4b524ed3d857148617feffffff02836d3c01000000001976a914fc25d6d5c94003bf5b0c7b640a248e2c637fcfb088ac7ada8202000000001976a914fbed3d9b11183209a57999d54d59f67c019e756c88ac6acb0700"
	spent    = "76a9144bfbaf6afb76cc5771bc6404810d1cc041a6933988ac"
)

var consensus = []string{"P2SH", "DERSIG", "NULLDUMMY", "CLTV", "CSV", "WITNESS", "TAPROOT"}

func req(spk string, flags []string) *request {
	return &request{
		ID:       7,
		TxHex:    spending,
		Prevouts: []prevout{{ScriptPubKeyHex: spk, AmountSats: 630482530}},
		Flags:    flags,
	}
}

func TestAcceptsRealSpend(t *testing.T) {
	if f := verify(req(spent, consensus)); f != nil {
		t.Fatalf("expected accept, got %v", f)
	}
	if f := verify(req(spent, nil)); f != nil {
		t.Fatalf("expected accept with no flags, got %v", f)
	}
}

func TestRejectsWrongScript(t *testing.T) {
	f := verify(req(strings.Replace(spent, "4bfb", "4bfc", 1), consensus))
	if f == nil || f.class != "EQUALVERIFY" {
		t.Fatalf("expected EQUALVERIFY, got %v", f)
	}
}

func TestBadRequests(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*request)
		class  string
	}{
		{"bad hex", func(r *request) { r.TxHex = "zz" }, "DESERIALIZE"},
		{"truncated tx", func(r *request) { r.TxHex = "0200" }, "DESERIALIZE"},
		{"trailing bytes", func(r *request) { r.TxHex += "00" }, "DESERIALIZE"},
		{"index out of range", func(r *request) { r.InputIndex = 5 }, "TX_INDEX"},
		{"prevout count", func(r *request) { r.Prevouts = append(r.Prevouts, r.Prevouts[0]) }, "DESERIALIZE"},
		{"bad script hex", func(r *request) { r.Prevouts[0].ScriptPubKeyHex = "q" }, "DESERIALIZE"},
		{"huge amount", func(r *request) { r.Prevouts[0].AmountSats = 1 << 63 }, "DESERIALIZE"},
		{"unknown flag", func(r *request) { r.Flags = []string{"NOPE"} }, "INVALID_FLAGS"},
	}
	for _, c := range cases {
		r := req(spent, nil)
		c.mutate(r)
		f := verify(r)
		if f == nil || f.class != c.class {
			t.Errorf("%s: expected %s, got %v", c.name, c.class, f)
		}
	}
}

func TestEveryFlagNameMaps(t *testing.T) {
	if len(flagMap) != 21 {
		t.Fatalf("expected 21 flags, have %d", len(flagMap))
	}
	for _, n := range consensus {
		if _, ok := flagMap[n]; !ok {
			t.Errorf("consensus flag %s unmapped", n)
		}
	}
}

func TestRunProtocol(t *testing.T) {
	good, _ := json.Marshal(req(spent, consensus))
	in := string(good) + "\n\n" + `{"id": 9, "tx_hex": 5}` + "\nnot json\n"
	var out bytes.Buffer
	if err := run(strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 responses, got %d: %q", len(lines), out.String())
	}
	var r [3]response
	for i := range lines {
		if err := json.Unmarshal([]byte(lines[i]), &r[i]); err != nil {
			t.Fatal(err)
		}
	}
	if !r[0].OK || r[0].ID != 7 || r[0].Impl != "btcd" || r[0].ErrorClass != "" {
		t.Errorf("unexpected first response: %+v", r[0])
	}
	if r[1].OK || r[1].ID != 9 || r[1].ErrorClass != "DESERIALIZE" {
		t.Errorf("unexpected second response: %+v", r[1])
	}
	if r[2].OK || r[2].ID != 0 || r[2].ErrorClass != "DESERIALIZE" {
		t.Errorf("unexpected third response: %+v", r[2])
	}
}

func TestLastLineWithoutNewline(t *testing.T) {
	good, _ := json.Marshal(req(spent, nil))
	var out bytes.Buffer
	if err := run(bytes.NewReader(good), &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"ok":true`) {
		t.Errorf("unexpected output %q", out.String())
	}
}
