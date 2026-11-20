// Command diffuzz-adapter-btcd is the diffuzz adapter for btcd's txscript engine.
//
// It speaks protocol v1: one JSON request per stdin line, one JSON response per stdout line.
// See docs/flag-mapping.md for the flag mapping and the adapter's documented limits.
package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"runtime/debug"

	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
)

const implName = "btcd"

type prevout struct {
	ScriptPubKeyHex string `json:"script_pubkey_hex"`
	AmountSats      uint64 `json:"amount_sats"`
}

type request struct {
	ID         uint64    `json:"id"`
	TxHex      string    `json:"tx_hex"`
	InputIndex uint32    `json:"input_index"`
	Prevouts   []prevout `json:"prevouts"`
	Flags      []string  `json:"flags"`
}

type response struct {
	ID          uint64 `json:"id"`
	OK          bool   `json:"ok"`
	ErrorClass  string `json:"error_class,omitempty"`
	RawError    string `json:"raw_error,omitempty"`
	Impl        string `json:"impl"`
	ImplVersion string `json:"impl_version"`
}

// failure is a rejection with its normalized class.
type failure struct {
	class string
	raw   string
}

func (f *failure) Error() string { return f.class + ": " + f.raw }

func fail(class, format string, args ...any) *failure {
	return &failure{class: class, raw: fmt.Sprintf(format, args...)}
}

// flagMap maps abstract diffuzz flag names to btcd script flags. The first seven are the
// consensus flags; the rest exist only for the opt-in policy mode.
var flagMap = map[string]txscript.ScriptFlags{
	"P2SH":      txscript.ScriptBip16,
	"DERSIG":    txscript.ScriptVerifyDERSignatures,
	"NULLDUMMY": txscript.ScriptStrictMultiSig,
	"CLTV":      txscript.ScriptVerifyCheckLockTimeVerify,
	"CSV":       txscript.ScriptVerifyCheckSequenceVerify,
	"WITNESS":   txscript.ScriptVerifyWitness,
	"TAPROOT":   txscript.ScriptVerifyTaproot,

	"STRICTENC":                             txscript.ScriptVerifyStrictEncoding,
	"LOW_S":                                 txscript.ScriptVerifyLowS,
	"SIGPUSHONLY":                           txscript.ScriptVerifySigPushOnly,
	"MINIMALDATA":                           txscript.ScriptVerifyMinimalData,
	"DISCOURAGE_UPGRADABLE_NOPS":            txscript.ScriptDiscourageUpgradableNops,
	"CLEANSTACK":                            txscript.ScriptVerifyCleanStack,
	"MINIMALIF":                             txscript.ScriptVerifyMinimalIf,
	"NULLFAIL":                              txscript.ScriptVerifyNullFail,
	"WITNESS_PUBKEYTYPE":                    txscript.ScriptVerifyWitnessPubKeyType,
	"DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM": txscript.ScriptVerifyDiscourageUpgradeableWitnessProgram,
	"CONST_SCRIPTCODE":                      txscript.ScriptVerifyConstScriptCode,
	"DISCOURAGE_UPGRADABLE_TAPROOT_VERSION": txscript.ScriptVerifyDiscourageUpgradeableTaprootVersion,
	"DISCOURAGE_OP_SUCCESS":                 txscript.ScriptVerifyDiscourageOpSuccess,
	"DISCOURAGE_UPGRADABLE_PUBKEYTYPE":      txscript.ScriptVerifyDiscourageUpgradeablePubkeyType,
}

// errorClasses maps btcd error codes to normalized diffuzz error classes.
var errorClasses = map[txscript.ErrorCode]string{
	txscript.ErrInvalidFlags:                        "INVALID_FLAGS",
	txscript.ErrInvalidIndex:                        "TX_INDEX",
	txscript.ErrEarlyReturn:                         "OP_RETURN",
	txscript.ErrEmptyStack:                          "EVAL_FALSE",
	txscript.ErrEvalFalse:                           "EVAL_FALSE",
	txscript.ErrScriptTooBig:                        "SCRIPT_SIZE",
	txscript.ErrElementTooBig:                       "PUSH_SIZE",
	txscript.ErrTooManyOperations:                   "OP_COUNT",
	txscript.ErrStackOverflow:                       "STACK_SIZE",
	txscript.ErrInvalidPubKeyCount:                  "PUBKEY_COUNT",
	txscript.ErrInvalidSignatureCount:               "SIG_COUNT",
	txscript.ErrNumberTooBig:                        "SCRIPT_NUM",
	txscript.ErrVerify:                              "VERIFY",
	txscript.ErrEqualVerify:                         "EQUALVERIFY",
	txscript.ErrNumEqualVerify:                      "NUMEQUALVERIFY",
	txscript.ErrCheckSigVerify:                      "CHECKSIGVERIFY",
	txscript.ErrCheckMultiSigVerify:                 "CHECKMULTISIGVERIFY",
	txscript.ErrDisabledOpcode:                      "DISABLED_OPCODE",
	txscript.ErrReservedOpcode:                      "BAD_OPCODE",
	txscript.ErrMalformedPush:                       "BAD_OPCODE",
	txscript.ErrInvalidStackOperation:               "INVALID_STACK_OPERATION",
	txscript.ErrUnbalancedConditional:               "UNBALANCED_CONDITIONAL",
	txscript.ErrMinimalData:                         "MINIMALDATA",
	txscript.ErrInvalidSigHashType:                  "SIG_HASHTYPE",
	txscript.ErrSigTooShort:                         "SIG_DER",
	txscript.ErrSigTooLong:                          "SIG_DER",
	txscript.ErrSigInvalidSeqID:                     "SIG_DER",
	txscript.ErrSigInvalidDataLen:                   "SIG_DER",
	txscript.ErrSigMissingSTypeID:                   "SIG_DER",
	txscript.ErrSigMissingSLen:                      "SIG_DER",
	txscript.ErrSigInvalidSLen:                      "SIG_DER",
	txscript.ErrSigInvalidRIntID:                    "SIG_DER",
	txscript.ErrSigZeroRLen:                         "SIG_DER",
	txscript.ErrSigNegativeR:                        "SIG_DER",
	txscript.ErrSigTooMuchRPadding:                  "SIG_DER",
	txscript.ErrSigInvalidSIntID:                    "SIG_DER",
	txscript.ErrSigZeroSLen:                         "SIG_DER",
	txscript.ErrSigNegativeS:                        "SIG_DER",
	txscript.ErrSigTooMuchSPadding:                  "SIG_DER",
	txscript.ErrSigHighS:                            "SIG_HIGH_S",
	txscript.ErrNotPushOnly:                         "SIG_PUSHONLY",
	txscript.ErrSigNullDummy:                        "SIG_NULLDUMMY",
	txscript.ErrPubKeyType:                          "PUBKEYTYPE",
	txscript.ErrCleanStack:                          "CLEANSTACK",
	txscript.ErrNullFail:                            "SIG_NULLFAIL",
	txscript.ErrWitnessMalleated:                    "WITNESS_MALLEATED",
	txscript.ErrWitnessMalleatedP2SH:                "WITNESS_MALLEATED_P2SH",
	txscript.ErrDiscourageUpgradableNOPs:            "DISCOURAGE_UPGRADABLE_NOPS",
	txscript.ErrNegativeLockTime:                    "NEGATIVE_LOCKTIME",
	txscript.ErrUnsatisfiedLockTime:                 "UNSATISFIED_LOCKTIME",
	txscript.ErrMinimalIf:                           "MINIMALIF",
	txscript.ErrDiscourageUpgradableWitnessProgram:  "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM",
	txscript.ErrWitnessProgramEmpty:                 "WITNESS_PROGRAM_WITNESS_EMPTY",
	txscript.ErrWitnessProgramMismatch:              "WITNESS_PROGRAM_MISMATCH",
	txscript.ErrWitnessProgramWrongLength:           "WITNESS_PROGRAM_WRONG_LENGTH",
	txscript.ErrWitnessUnexpected:                   "WITNESS_UNEXPECTED",
	txscript.ErrWitnessPubKeyType:                   "WITNESS_PUBKEYTYPE",
	txscript.ErrDiscourageOpSuccess:                 "DISCOURAGE_OP_SUCCESS",
	txscript.ErrDiscourageUpgradeableTaprootVersion: "DISCOURAGE_UPGRADABLE_TAPROOT_VERSION",
	txscript.ErrTapscriptCheckMultisig:              "TAPSCRIPT_CHECKMULTISIG",
	txscript.ErrDiscourageUpgradeablePubKeyType:     "DISCOURAGE_UPGRADABLE_PUBKEYTYPE",
	txscript.ErrTaprootSigInvalid:                   "SCHNORR_SIG",
	txscript.ErrTaprootMerkleProofInvalid:           "WITNESS_PROGRAM_MISMATCH",
	txscript.ErrTaprootOutputKeyParityMismatch:      "WITNESS_PROGRAM_MISMATCH",
	txscript.ErrControlBlockTooSmall:                "TAPROOT_WRONG_CONTROL_SIZE",
	txscript.ErrControlBlockTooLarge:                "TAPROOT_WRONG_CONTROL_SIZE",
	txscript.ErrControlBlockInvalidLength:           "TAPROOT_WRONG_CONTROL_SIZE",
	txscript.ErrInvalidTaprootSigLen:                "SCHNORR_SIG_SIZE",
	txscript.ErrTaprootPubkeyIsEmpty:                "TAPSCRIPT_EMPTY_PUBKEY",
	txscript.ErrTaprootMaxSigOps:                    "TAPSCRIPT_VALIDATION_WEIGHT",
	txscript.ErrNonConstScriptCode:                  "OP_CODESEPARATOR",
	txscript.ErrCodeSeparator:                       "OP_CODESEPARATOR",
}

func classify(err error) *failure {
	var serr txscript.Error
	if errors.As(err, &serr) {
		class, ok := errorClasses[serr.ErrorCode]
		if !ok {
			class = "UNKNOWN"
		}
		return &failure{class: class, raw: serr.ErrorCode.String() + ": " + serr.Description}
	}
	return &failure{class: "UNKNOWN", raw: err.Error()}
}

func parseFlags(names []string) (txscript.ScriptFlags, *failure) {
	var flags txscript.ScriptFlags
	for _, n := range names {
		f, ok := flagMap[n]
		if !ok {
			return 0, fail("INVALID_FLAGS", "unknown flag %q", n)
		}
		flags |= f
	}
	return flags, nil
}

// verify runs one request through btcd. A nil return means the input was accepted.
func verify(req *request) (f *failure) {
	// A panic inside btcd is a finding in its own right; report it instead of dying.
	defer func() {
		if r := recover(); r != nil {
			f = fail("CRASH", "panic: %v\n%s", r, debug.Stack())
		}
	}()

	flags, ff := parseFlags(req.Flags)
	if ff != nil {
		return ff
	}

	raw, err := hex.DecodeString(req.TxHex)
	if err != nil {
		return fail("DESERIALIZE", "tx_hex is not valid hex")
	}
	rd := bytes.NewReader(raw)
	var tx wire.MsgTx
	if err := tx.Deserialize(rd); err != nil {
		return fail("DESERIALIZE", "tx decode: %v", err)
	}
	if rd.Len() != 0 {
		return fail("DESERIALIZE", "%d trailing bytes after transaction", rd.Len())
	}
	if len(req.Prevouts) != len(tx.TxIn) {
		return fail("DESERIALIZE", "%d prevouts for %d inputs", len(req.Prevouts), len(tx.TxIn))
	}
	if int(req.InputIndex) >= len(tx.TxIn) {
		return fail("TX_INDEX", "input index %d out of range", req.InputIndex)
	}

	scripts := make([][]byte, len(req.Prevouts))
	prevOuts := make(map[wire.OutPoint]*wire.TxOut, len(req.Prevouts))
	for i, p := range req.Prevouts {
		s, err := hex.DecodeString(p.ScriptPubKeyHex)
		if err != nil {
			return fail("DESERIALIZE", "prevout %d script is not valid hex", i)
		}
		if p.AmountSats > math.MaxInt64 {
			return fail("DESERIALIZE", "prevout %d amount exceeds int64", i)
		}
		scripts[i] = s
		op := tx.TxIn[i].PreviousOutPoint
		out := wire.NewTxOut(int64(p.AmountSats), s)
		// btcd looks spent outputs up by outpoint, so two inputs spending the same outpoint
		// with different declared prevouts cannot be represented. Such a transaction is
		// invalid anyway (duplicate inputs); abstain rather than guess.
		if prev, dup := prevOuts[op]; dup {
			if prev.Value != out.Value || !bytes.Equal(prev.PkScript, out.PkScript) {
				return fail("UNSUPPORTED", "duplicate outpoint with conflicting prevouts")
			}
		}
		prevOuts[op] = out
	}

	idx := int(req.InputIndex)
	fetcher := txscript.NewMultiPrevOutFetcher(prevOuts)
	hashCache := txscript.NewTxSigHashes(&tx, fetcher)
	vm, err := txscript.NewEngine(
		scripts[idx], &tx, idx, flags, nil, hashCache,
		int64(req.Prevouts[idx].AmountSats), fetcher,
	)
	if err != nil {
		return classify(err)
	}
	if err := vm.Execute(); err != nil {
		return classify(err)
	}
	return nil
}

func implVersion() string {
	version := "txscript/v2 (unknown version)"
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range info.Deps {
			if dep.Path == "github.com/btcsuite/btcd/txscript/v2" {
				version = "btcd txscript/v2 " + dep.Version
			}
		}
	}
	return version
}

func handleLine(line []byte, version string) response {
	resp := response{Impl: implName, ImplVersion: version}
	var req request
	if err := json.Unmarshal(line, &req); err != nil {
		// Echo the id if the line is at least JSON with one, so the caller stays in sync.
		var partial struct {
			ID uint64 `json:"id"`
		}
		_ = json.Unmarshal(line, &partial)
		resp.ID = partial.ID
		resp.ErrorClass = "DESERIALIZE"
		resp.RawError = "bad request: " + err.Error()
		return resp
	}
	resp.ID = req.ID
	if f := verify(&req); f != nil {
		resp.ErrorClass = f.class
		resp.RawError = f.raw
		return resp
	}
	resp.OK = true
	return resp
}

func run(in io.Reader, out io.Writer) error {
	version := implVersion()
	rd := bufio.NewReaderSize(in, 1<<20)
	wr := bufio.NewWriter(out)
	enc := json.NewEncoder(wr)
	for {
		line, err := rd.ReadBytes('\n')
		if len(bytes.TrimSpace(line)) > 0 {
			var out any
			if isAux(line) {
				out = handleAux(line)
			} else {
				out = handleLine(line, version)
			}
			if encErr := enc.Encode(out); encErr != nil {
				return encErr
			}
			// Flush every answer: if a later request hangs, earlier answers must already be out,
			// or the orchestrator blames a timeout on the wrong case.
			if flushErr := wr.Flush(); flushErr != nil {
				return flushErr
			}
		}
		if err != nil {
			if flushErr := wr.Flush(); flushErr != nil {
				return flushErr
			}
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

func main() {
	if err := run(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "diffuzz-adapter-btcd:", err)
		os.Exit(1)
	}
}
