// diffuzz adapter for NBitcoin's script interpreter.
//
// Speaks protocol v1: one JSON request per stdin line, one JSON response per stdout line.
// See docs/flag-mapping.md for the flag mapping and the adapter's documented limits.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using NBitcoin;

public sealed class Prevout
{
    [JsonPropertyName("script_pubkey_hex")] public string ScriptPubKeyHex { get; set; } = "";
    [JsonPropertyName("amount_sats")] public ulong AmountSats { get; set; }
}

public sealed class Request
{
    [JsonPropertyName("id")] public ulong Id { get; set; }
    [JsonPropertyName("tx_hex")] public string TxHex { get; set; } = "";
    [JsonPropertyName("input_index")] public uint InputIndex { get; set; }
    [JsonPropertyName("prevouts")] public List<Prevout> Prevouts { get; set; } = new();
    [JsonPropertyName("flags")] public List<string> Flags { get; set; } = new();
}

public sealed class Response
{
    [JsonPropertyName("id")] public ulong Id { get; set; }
    [JsonPropertyName("ok")] public bool Ok { get; set; }
    [JsonPropertyName("error_class")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ErrorClass { get; set; }
    [JsonPropertyName("raw_error")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? RawError { get; set; }
    [JsonPropertyName("impl")] public string Impl { get; set; } = "nbitcoin";
    [JsonPropertyName("impl_version")] public string ImplVersion { get; set; } = "";
}

public sealed class Failure : Exception
{
    public string Class { get; }
    public Failure(string cls, string message) : base(message) { Class = cls; }
}

public static class Adapter
{
    // Abstract diffuzz flag names -> NBitcoin flags. The first seven are consensus flags.
    static readonly Dictionary<string, ScriptVerify> FlagMap = new()
    {
        ["P2SH"] = ScriptVerify.P2SH,
        ["DERSIG"] = ScriptVerify.DerSig,
        ["NULLDUMMY"] = ScriptVerify.NullDummy,
        ["CLTV"] = ScriptVerify.CheckLockTimeVerify,
        ["CSV"] = ScriptVerify.CheckSequenceVerify,
        ["WITNESS"] = ScriptVerify.Witness,
        ["TAPROOT"] = ScriptVerify.Taproot,

        ["STRICTENC"] = ScriptVerify.StrictEnc,
        ["LOW_S"] = ScriptVerify.LowS,
        ["SIGPUSHONLY"] = ScriptVerify.SigPushOnly,
        ["MINIMALDATA"] = ScriptVerify.MinimalData,
        ["DISCOURAGE_UPGRADABLE_NOPS"] = ScriptVerify.DiscourageUpgradableNops,
        ["CLEANSTACK"] = ScriptVerify.CleanStack,
        ["MINIMALIF"] = ScriptVerify.MinimalIf,
        ["NULLFAIL"] = ScriptVerify.NullFail,
        ["WITNESS_PUBKEYTYPE"] = ScriptVerify.WitnessPubkeyType,
        ["DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM"] = ScriptVerify.DiscourageUpgradableWitnessProgram,
        ["CONST_SCRIPTCODE"] = ScriptVerify.ConstScriptCode,
        ["DISCOURAGE_UPGRADABLE_TAPROOT_VERSION"] = ScriptVerify.DiscourageUpgradableTaprootVersion,
        ["DISCOURAGE_OP_SUCCESS"] = ScriptVerify.DiscourageOpSuccess,
    };

    // diffuzz error classes that have a same-named NBitcoin ScriptError once underscores and
    // case are ignored (both follow Bitcoin Core's ScriptError names).
    static readonly string[] Classes =
    {
        "EVAL_FALSE", "OP_RETURN", "SCRIPT_SIZE", "PUSH_SIZE", "OP_COUNT", "STACK_SIZE",
        "SIG_COUNT", "PUBKEY_COUNT", "VERIFY", "EQUALVERIFY", "CHECKMULTISIGVERIFY",
        "CHECKSIGVERIFY", "NUMEQUALVERIFY", "BAD_OPCODE", "DISABLED_OPCODE",
        "INVALID_STACK_OPERATION", "INVALID_ALTSTACK_OPERATION", "UNBALANCED_CONDITIONAL",
        "NEGATIVE_LOCKTIME", "UNSATISFIED_LOCKTIME", "SIG_HASHTYPE", "SIG_DER", "MINIMALDATA",
        "SIG_PUSHONLY", "SIG_HIGH_S", "SIG_NULLDUMMY", "PUBKEYTYPE", "CLEANSTACK", "MINIMALIF",
        "SIG_NULLFAIL", "DISCOURAGE_UPGRADABLE_NOPS", "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM",
        "DISCOURAGE_UPGRADABLE_TAPROOT_VERSION", "DISCOURAGE_OP_SUCCESS",
        "DISCOURAGE_UPGRADABLE_PUBKEYTYPE", "WITNESS_PROGRAM_WRONG_LENGTH",
        "WITNESS_PROGRAM_WITNESS_EMPTY", "WITNESS_PROGRAM_MISMATCH", "WITNESS_MALLEATED",
        "WITNESS_MALLEATED_P2SH", "WITNESS_UNEXPECTED", "WITNESS_PUBKEYTYPE",
        "SCHNORR_SIG_SIZE", "SCHNORR_SIG_HASHTYPE", "SCHNORR_SIG", "TAPROOT_WRONG_CONTROL_SIZE",
        "TAPSCRIPT_VALIDATION_WEIGHT", "TAPSCRIPT_CHECKMULTISIG", "TAPSCRIPT_MINIMALIF",
        "TAPSCRIPT_EMPTY_PUBKEY", "OP_CODESEPARATOR", "SIG_FINDANDDELETE",
    };

    static readonly Dictionary<string, string> ClassByName =
        Classes.ToDictionary(c => c.Replace("_", ""), c => c);

    public static readonly string Version =
        "NBitcoin " + (typeof(Transaction).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
            .Split('+')[0] ?? typeof(Transaction).Assembly.GetName().Version?.ToString() ?? "unknown");

    public static string Classify(ScriptError error)
    {
        var key = error.ToString().ToUpperInvariant();
        return ClassByName.TryGetValue(key, out var cls) ? cls : "UNKNOWN";
    }

    static byte[] Hex(string s, string what)
    {
        try { return Convert.FromHexString(s); }
        catch (FormatException) { throw new Failure("DESERIALIZE", what + " is not valid hex"); }
    }

    /// Verify one request. Returns normally if the input is accepted, throws Failure otherwise.
    public static void Verify(Request req)
    {
        var flags = ScriptVerify.None;
        foreach (var name in req.Flags)
        {
            if (!FlagMap.TryGetValue(name, out var f))
                throw new Failure("INVALID_FLAGS", $"flag {name} has no NBitcoin equivalent");
            flags |= f;
        }

        var raw = Hex(req.TxHex, "tx_hex");
        Transaction tx;
        try { tx = Transaction.Load(raw, Network.Main); }
        catch (Exception e) { throw new Failure("DESERIALIZE", "tx decode: " + e.Message); }
        // Reject trailing bytes and non-canonical encodings, as Core's library does.
        if (tx.ToBytes().Length != raw.Length)
            throw new Failure("DESERIALIZE", "transaction does not re-serialize to the same length");
        if (req.Prevouts.Count != tx.Inputs.Count)
            throw new Failure("DESERIALIZE", $"{req.Prevouts.Count} prevouts for {tx.Inputs.Count} inputs");
        if (req.InputIndex >= tx.Inputs.Count)
            throw new Failure("TX_INDEX", $"input index {req.InputIndex} out of range");

        var spent = new TxOut[req.Prevouts.Count];
        for (var i = 0; i < spent.Length; i++)
        {
            var p = req.Prevouts[i];
            if (p.AmountSats > long.MaxValue)
                throw new Failure("DESERIALIZE", $"prevout {i} amount exceeds int64");
            var script = Script.FromBytesUnsafe(Hex(p.ScriptPubKeyHex, $"prevout {i} script"));
            spent[i] = new TxOut(Money.Satoshis((long)p.AmountSats), script);
        }

        var index = (int)req.InputIndex;
        var input = tx.Inputs[index];
        var checker = new TransactionChecker(tx, index, spent[index], tx.PrecomputeTransactionData(spent));
        var ctx = new ScriptEvaluationContext { ScriptVerify = flags };
        var ok = ctx.VerifyScript(input.ScriptSig, input.WitScript, spent[index].ScriptPubKey, checker);
        if (!ok)
            throw new Failure(Classify(ctx.Error), ctx.Error.ToString());
    }

    public static Response HandleLine(string line)
    {
        var resp = new Response { ImplVersion = Version };
        Request? req;
        try
        {
            req = JsonSerializer.Deserialize<Request>(line);
            if (req is null) throw new JsonException("null request");
        }
        catch (Exception e) when (e is JsonException or NotSupportedException or InvalidOperationException)
        {
            // Echo the id if the line is at least JSON with one, so the caller stays in sync.
            try
            {
                using var doc = JsonDocument.Parse(line);
                if (doc.RootElement.ValueKind == JsonValueKind.Object &&
                    doc.RootElement.TryGetProperty("id", out var id) && id.TryGetUInt64(out var n))
                    resp.Id = n;
            }
            catch (JsonException) { }
            resp.ErrorClass = "DESERIALIZE";
            resp.RawError = "bad request: " + e.Message;
            return resp;
        }

        resp.Id = req.Id;
        try
        {
            Verify(req);
            resp.Ok = true;
        }
        catch (Failure f)
        {
            resp.ErrorClass = f.Class;
            resp.RawError = f.Message;
        }
        catch (Exception e)
        {
            // An unexpected exception inside the implementation is a finding in its own right.
            resp.ErrorClass = "CRASH";
            resp.RawError = e.GetType().Name + ": " + e.Message + "\n" + e.StackTrace;
        }
        return resp;
    }

    public static int Main(string[] args)
    {
        var utf8 = new UTF8Encoding(false);
        using var stdin = new StreamReader(Console.OpenStandardInput(), utf8, false, 1 << 20);
        using var stdout = new StreamWriter(Console.OpenStandardOutput(), utf8, 1 << 16);
        stdout.NewLine = "\n";
        string? line;
        while ((line = stdin.ReadLine()) != null)
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            stdout.WriteLine(JsonSerializer.Serialize(HandleLine(line)));
            // Flush every response: the caller may be waiting for exactly this one, and
            // StreamReader offers no reliable non-blocking "more input buffered?" check.
            stdout.Flush();
        }
        stdout.Flush();
        return 0;
    }
}
