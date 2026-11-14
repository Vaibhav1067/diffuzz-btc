// Auxiliary protocol operations: transaction info and signature hashes.
// See crates/types/src/auxop.rs for the wire format.

using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using NBitcoin;

public sealed class AuxRequest
{
    [JsonPropertyName("id")] public ulong Id { get; set; }
    [JsonPropertyName("op")] public string Op { get; set; } = "";
    [JsonPropertyName("kind")] public string Kind { get; set; } = "";
    [JsonPropertyName("tx_hex")] public string TxHex { get; set; } = "";
    [JsonPropertyName("input_index")] public uint InputIndex { get; set; }
    [JsonPropertyName("script_hex")] public string ScriptHex { get; set; } = "";
    [JsonPropertyName("hash_type")] public uint HashType { get; set; }
    [JsonPropertyName("amount_sats")] public ulong AmountSats { get; set; }
    [JsonPropertyName("prevouts")] public List<Prevout> Prevouts { get; set; } = new();
    [JsonPropertyName("annex_hex")] public string? AnnexHex { get; set; }
    [JsonPropertyName("leaf_hash_hex")] public string? LeafHashHex { get; set; }
    [JsonPropertyName("codesep_pos")] public uint CodesepPos { get; set; }
}

public sealed class AuxResponse
{
    [JsonPropertyName("id")] public ulong Id { get; set; }
    [JsonPropertyName("ok")] public bool Ok { get; set; }
    [JsonPropertyName("unsupported")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool Unsupported { get; set; }
    [JsonPropertyName("error")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Error { get; set; }
    [JsonPropertyName("txid")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Txid { get; set; }
    [JsonPropertyName("wtxid")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Wtxid { get; set; }
    [JsonPropertyName("hex")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Hex { get; set; }
    [JsonPropertyName("digest")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Digest { get; set; }
}

public static class AuxOps
{
    static string Lower(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();

    static Transaction Decode(string hex)
    {
        byte[] raw;
        try { raw = Convert.FromHexString(hex); }
        catch (FormatException) { throw new InvalidDataException("tx_hex is not valid hex"); }
        Transaction tx;
        try { tx = Transaction.Load(raw, Network.Main); }
        catch (Exception e) { throw new InvalidDataException("tx decode: " + e.Message); }
        if (tx.ToBytes().Length != raw.Length)
            throw new InvalidDataException("transaction does not re-serialize to the same length");
        return tx;
    }

    static void Txinfo(AuxRequest req, AuxResponse resp)
    {
        var tx = Decode(req.TxHex);
        // uint256.ToBytes() is little-endian, i.e. the raw digest bytes.
        resp.Txid = Lower(tx.GetHash().ToBytes());
        resp.Wtxid = Lower(tx.GetWitHash().ToBytes());
        resp.Hex = Lower(tx.ToBytes());
        resp.Ok = true;
    }

    static void Sighash(AuxRequest req, AuxResponse resp)
    {
        var tx = Decode(req.TxHex);
        var index = (int)req.InputIndex;
        if (req.InputIndex >= tx.Inputs.Count)
        {
            resp.Error = "input index out of range";
            return;
        }
        if (req.AmountSats > long.MaxValue)
        {
            resp.Error = "amount exceeds int64";
            return;
        }
        var script = Script.FromBytesUnsafe(Convert.FromHexString(req.ScriptHex));
        uint256 digest;
        switch (req.Kind)
        {
            case "legacy":
            case "bip143":
            {
                var spent = new TxOut(Money.Satoshis((long)req.AmountSats), script);
                var version = req.Kind == "legacy" ? HashVersion.Original : HashVersion.WitnessV0;
                try
                {
                    digest = tx.GetSignatureHash(script, index, (SigHash)req.HashType, spent, version);
                }
                catch (EndOfStreamException)
                {
                    // NBitcoin parses the scriptCode into ops; Core hashes unparsable bytes as-is.
                    resp.Unsupported = true;
                    resp.Error = "GetSignatureHash cannot parse this scriptCode";
                    return;
                }
                break;
            }
            case "bip341":
            {
                if (req.Prevouts.Count != tx.Inputs.Count)
                {
                    resp.Error = "prevout count does not match inputs";
                    return;
                }
                if (req.HashType > 0xff)
                {
                    resp.Error = "taproot hash type is one byte";
                    return;
                }
                var outs = new TxOut[req.Prevouts.Count];
                for (var i = 0; i < outs.Length; i++)
                {
                    if (req.Prevouts[i].AmountSats > long.MaxValue)
                    {
                        resp.Error = "bad prevout";
                        return;
                    }
                    outs[i] = new TxOut(
                        Money.Satoshis((long)req.Prevouts[i].AmountSats),
                        Script.FromBytesUnsafe(Convert.FromHexString(req.Prevouts[i].ScriptPubKeyHex)));
                }
                var data = req.LeafHashHex is null
                    ? new TaprootExecutionData(index)
                    : new TaprootExecutionData(index, new uint256(Convert.FromHexString(req.LeafHashHex)));
                if (!TaprootExecutionData.IsValidSigHash((byte)req.HashType))
                {
                    // BIP341 defines no digest for this hash type.
                    resp.Error = "invalid taproot hash type";
                    return;
                }
                data.SigHash = (TaprootSigHash)req.HashType;
                data.CodeseparatorPosition = req.CodesepPos;
                if (req.AnnexHex is not null)
                {
                    // sha_annex = SHA256(compact_size(len) || annex)
                    var annex = Convert.FromHexString(req.AnnexHex);
                    using var ms = new MemoryStream();
                    var bs = new BitcoinStream(ms, true);
                    bs.ReadWriteAsVarString(ref annex);
                    data.AnnexHash = new uint256(SHA256.HashData(ms.ToArray()));
                }
                digest = tx.GetSignatureHashTaproot(outs, data);
                break;
            }
            default:
                resp.Unsupported = true;
                resp.Error = "unknown sighash kind " + req.Kind;
                return;
        }
        resp.Digest = Lower(digest.ToBytes());
        resp.Ok = true;
    }

    /// True if the JSON line carries an "op" field.
    public static bool IsAux(string line)
    {
        try
        {
            using var doc = JsonDocument.Parse(line);
            return doc.RootElement.ValueKind == JsonValueKind.Object &&
                   doc.RootElement.TryGetProperty("op", out _);
        }
        catch (JsonException) { return false; }
    }

    public static AuxResponse Handle(string line)
    {
        var resp = new AuxResponse();
        AuxRequest? req;
        try
        {
            req = JsonSerializer.Deserialize<AuxRequest>(line);
            if (req is null) throw new JsonException("null request");
        }
        catch (Exception e) when (e is JsonException or NotSupportedException or InvalidOperationException)
        {
            resp.Error = "bad request: " + e.Message;
            return resp;
        }
        resp.Id = req.Id;
        try
        {
            switch (req.Op)
            {
                case "txinfo": Txinfo(req, resp); break;
                case "sighash": Sighash(req, resp); break;
                default:
                    resp.Unsupported = true;
                    resp.Error = "unknown op " + req.Op;
                    break;
            }
        }
        catch (InvalidDataException e)
        {
            resp.Ok = false;
            resp.Error = e.Message;
        }
        catch (FormatException e)
        {
            resp.Ok = false;
            resp.Error = "bad hex: " + e.Message;
        }
        catch (Exception e)
        {
            resp = new AuxResponse { Id = req.Id, Error = "CRASH: " + e.GetType().Name + ": " + e.Message };
        }
        return resp;
    }
}
