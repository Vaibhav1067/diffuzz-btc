package main

// Auxiliary protocol operations: transaction info and signature hashes. See
// crates/types/src/auxop.rs for the wire format.

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"

	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
)

type auxRequest struct {
	ID          uint64    `json:"id"`
	Op          string    `json:"op"`
	Kind        string    `json:"kind"`
	TxHex       string    `json:"tx_hex"`
	InputIndex  uint32    `json:"input_index"`
	ScriptHex   string    `json:"script_hex"`
	HashType    uint32    `json:"hash_type"`
	AmountSats  uint64    `json:"amount_sats"`
	Prevouts    []prevout `json:"prevouts"`
	AnnexHex    *string   `json:"annex_hex"`
	LeafHashHex *string   `json:"leaf_hash_hex"`
	CodesepPos  uint32    `json:"codesep_pos"`
}

type auxResponse struct {
	ID          uint64  `json:"id"`
	OK          bool    `json:"ok"`
	Unsupported bool    `json:"unsupported,omitempty"`
	Error       string  `json:"error,omitempty"`
	Txid        string  `json:"txid,omitempty"`
	Wtxid       string  `json:"wtxid,omitempty"`
	Weight      *uint64 `json:"weight,omitempty"`
	Hex         string  `json:"hex,omitempty"`
	Digest      string  `json:"digest,omitempty"`
}

// isAux reports whether a request line carries an "op" field.
func isAux(line []byte) bool {
	var probe struct {
		Op *string `json:"op"`
	}
	return json.Unmarshal(line, &probe) == nil && probe.Op != nil
}

func decodeTx(txHex string) (*wire.MsgTx, error) {
	raw, err := hex.DecodeString(txHex)
	if err != nil {
		return nil, fmt.Errorf("tx_hex is not valid hex")
	}
	rd := bytes.NewReader(raw)
	var tx wire.MsgTx
	if err := tx.Deserialize(rd); err != nil {
		return nil, fmt.Errorf("tx decode: %v", err)
	}
	if rd.Len() != 0 {
		return nil, fmt.Errorf("%d trailing bytes after transaction", rd.Len())
	}
	return &tx, nil
}

func txinfo(req *auxRequest, resp *auxResponse) {
	tx, err := decodeTx(req.TxHex)
	if err != nil {
		resp.Error = err.Error()
		return
	}
	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		resp.Error = "serialize: " + err.Error()
		return
	}
	txid := tx.TxHash()
	wtxid := tx.WitnessHash()
	weight := uint64(tx.SerializeSizeStripped()*3 + tx.SerializeSize())
	resp.OK = true
	resp.Txid = hex.EncodeToString(txid[:])
	resp.Wtxid = hex.EncodeToString(wtxid[:])
	resp.Weight = &weight
	resp.Hex = hex.EncodeToString(buf.Bytes())
}

func sighash(req *auxRequest, resp *auxResponse) {
	tx, err := decodeTx(req.TxHex)
	if err != nil {
		resp.Error = err.Error()
		return
	}
	idx := int(req.InputIndex)
	if idx >= len(tx.TxIn) {
		resp.Error = "input index out of range"
		return
	}
	script, err := hex.DecodeString(req.ScriptHex)
	if err != nil {
		resp.Error = "script_hex is not valid hex"
		return
	}
	hashType := txscript.SigHashType(req.HashType)

	var digest []byte
	switch req.Kind {
	case "legacy":
		// The public API refuses scripts it cannot parse, where Core hashes the raw bytes.
		digest, err = txscript.CalcSignatureHash(script, hashType, tx, idx)
		if err != nil {
			resp.Unsupported = true
			resp.Error = "CalcSignatureHash: " + err.Error()
			return
		}
	case "bip143":
		if req.AmountSats > math.MaxInt64 {
			resp.Error = "amount exceeds int64"
			return
		}
		fetcher := txscript.NewCannedPrevOutputFetcher(nil, int64(req.AmountSats))
		hashes := txscript.NewTxSigHashes(tx, fetcher)
		digest, err = txscript.CalcWitnessSigHash(script, hashes, hashType, tx, idx, int64(req.AmountSats))
		if err != nil {
			resp.Unsupported = true
			resp.Error = "CalcWitnessSigHash: " + err.Error()
			return
		}
	case "bip341":
		if len(req.Prevouts) != len(tx.TxIn) {
			resp.Error = "prevout count does not match inputs"
			return
		}
		prevOuts := make(map[wire.OutPoint]*wire.TxOut, len(req.Prevouts))
		for i, p := range req.Prevouts {
			s, err := hex.DecodeString(p.ScriptPubKeyHex)
			if err != nil || p.AmountSats > math.MaxInt64 {
				resp.Error = "bad prevout"
				return
			}
			op := tx.TxIn[i].PreviousOutPoint
			if _, dup := prevOuts[op]; dup {
				resp.Unsupported = true
				resp.Error = "duplicate outpoint: prevouts are keyed by outpoint in btcd"
				return
			}
			prevOuts[op] = wire.NewTxOut(int64(p.AmountSats), s)
		}
		fetcher := txscript.NewMultiPrevOutFetcher(prevOuts)
		hashes := txscript.NewTxSigHashes(tx, fetcher)
		var opts []txscript.TaprootSigHashOption
		if req.AnnexHex != nil {
			annex, err := hex.DecodeString(*req.AnnexHex)
			if err != nil {
				resp.Error = "annex_hex is not valid hex"
				return
			}
			opts = append(opts, txscript.WithAnnex(annex))
		}
		if req.LeafHashHex != nil {
			// Script path: script_hex is the tapscript leaf (leaf version 0xc0).
			leaf := txscript.NewBaseTapLeaf(script)
			opts = append(opts, txscript.WithBaseTapscriptVersion(req.CodesepPos, leafHash(leaf)))
			digest, err = txscript.CalcTapscriptSignaturehash(hashes, hashType, tx, idx, fetcher, leaf, opts...)
		} else if req.AnnexHex != nil {
			// The public key-path function takes no annex option.
			resp.Unsupported = true
			resp.Error = "CalcTaprootSignatureHash has no annex parameter"
			return
		} else {
			digest, err = txscript.CalcTaprootSignatureHash(hashes, hashType, tx, idx, fetcher)
		}
		if err != nil {
			// An undefined hash type or a missing SIGHASH_SINGLE output: no digest exists.
			resp.Error = "CalcTaprootSignatureHash: " + err.Error()
			return
		}
	default:
		resp.Unsupported = true
		resp.Error = "unknown sighash kind " + req.Kind
		return
	}
	resp.OK = true
	resp.Digest = hex.EncodeToString(digest)
}

func leafHash(leaf txscript.TapLeaf) []byte {
	h := leaf.TapHash()
	return h[:]
}

func handleAux(line []byte) (resp auxResponse) {
	var req auxRequest
	if err := json.Unmarshal(line, &req); err != nil {
		var partial struct {
			ID uint64 `json:"id"`
		}
		_ = json.Unmarshal(line, &partial)
		return auxResponse{ID: partial.ID, Error: "bad request: " + err.Error()}
	}
	resp.ID = req.ID
	defer func() {
		if r := recover(); r != nil {
			resp = auxResponse{ID: req.ID, Error: fmt.Sprintf("CRASH: panic: %v", r)}
		}
	}()
	switch req.Op {
	case "txinfo":
		txinfo(&req, &resp)
	case "sighash":
		sighash(&req, &resp)
	default:
		resp.Unsupported = true
		resp.Error = "unknown op " + req.Op
	}
	return resp
}
