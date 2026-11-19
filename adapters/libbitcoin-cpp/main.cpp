// diffuzz adapter for libbitcoin-system v4: protocol v1 (one JSON request per stdin line, one
// JSON response per stdout line). Verifies one input with machine::interpreter::connect after
// attaching every spent output to its input (taproot needs all of them).
//
// Auxiliary requests (with an "op" field) are answered "unsupported".

#include <bitcoin/system.hpp>
#include <nlohmann/json.hpp>

#include <exception>
#include <iostream>
#include <string>
#include <vector>

using namespace libbitcoin::system;
using njson = nlohmann::json;

#ifndef LIBBITCOIN_PIN
#define LIBBITCOIN_PIN "unknown"
#endif

static const char* IMPL = "libbitcoin";
static const std::string VERSION = std::string("libbitcoin-system ") + LIBBITCOIN_PIN;

static njson respond(uint64_t id, bool ok, const std::string& cls, const std::string& raw)
{
    njson r = {{"id", id}, {"ok", ok}, {"impl", IMPL}, {"impl_version", VERSION}};
    if (!ok)
    {
        r["error_class"] = cls;
        r["raw_error"] = raw;
    }
    return r;
}

// Abstract consensus flag to libbitcoin rule bits. Policy flags have no mapping.
static bool map_flag(const std::string& f, uint32_t& out)
{
    using chain::flags;
    if (f == "P2SH") out |= flags::bip16_rule;
    else if (f == "DERSIG") out |= flags::bip66_rule;
    else if (f == "NULLDUMMY") out |= flags::bip147_rule;
    else if (f == "CLTV") out |= flags::bip65_rule;
    else if (f == "CSV") out |= flags::bip112_rule;
    else if (f == "WITNESS") out |= flags::bip141_rule | flags::bip143_rule;
    else if (f == "TAPROOT") out |= flags::bip341_rule | flags::bip342_rule;
    else return false;
    return true;
}

// Auxiliary operations (crates/types/src/auxop.rs). Digests and ids are raw byte order.
static njson aux_fail(uint64_t id, const std::string& why)
{
    return {{"id", id}, {"ok", false}, {"error", why}};
}

static njson aux_unsupported(uint64_t id, const std::string& why)
{
    return {{"id", id}, {"ok", false}, {"unsupported", true}, {"error", why}};
}

// Remove OP_CODESEPARATORs the way Core's SerializeScriptCode does: walk opcodes, drop each
// separator, copy everything from the first unparsable opcode on. libbitcoin's legacy sighash
// writes the subscript verbatim and leaves this to its caller (the interpreter).
static data_chunk strip_codeseparators(const data_chunk& s)
{
    data_chunk out;
    size_t i = 0;
    while (i < s.size())
    {
        const uint8_t op = s[i];
        size_t header = 1, push = 0;
        if (op >= 0x01 && op <= 0x4b) push = op;
        else if (op >= 0x4c && op <= 0x4e)
        {
            const size_t len = op == 0x4c ? 1 : op == 0x4d ? 2 : 4;
            header = 1 + len;
            if (i + header > s.size()) break;
            for (size_t k = len; k > 0; --k) push = (push << 8) | s[i + k];
        }
        if (i + header > s.size() || push > s.size() - i - header) break;
        if (op != 0xab) out.insert(out.end(), s.begin() + i, s.begin() + i + header + push);
        i += header + push;
    }
    out.insert(out.end(), s.begin() + i, s.end());
    return out;
}

static bool decode_tx(const std::string& hex, data_chunk& raw, std::string& err)
{
    if (!decode_base16(raw, hex)) { err = "tx_hex is not valid hex"; return false; }
    return true;
}

static njson handle_aux(uint64_t id, const njson& req)
{
    try
    {
        const auto op = req.at("op").get<std::string>();
        data_chunk raw;
        std::string err;
        if (op != "txinfo" && op != "sighash")
            return aux_unsupported(id, "unknown op " + op);
        if (!decode_tx(req.at("tx_hex").get<std::string>(), raw, err))
            return aux_fail(id, err);
        const chain::transaction tx(raw, true);
        if (!tx.is_valid() || tx.serialized_size(true) != raw.size())
            return aux_fail(id, "transaction does not decode exactly");

        if (op == "txinfo")
        {
            // libbitcoin takes 0x00 as the segwit marker only when the next byte is 0x01, else
            // as a zero input count, so `00 <n>` with n != 1 parses as a zero-input transaction
            // where Core rejects the unknown flag. Zero-input transactions are invalid in both
            // (transaction::check, error::empty_transaction), so the decodings are not comparable.
            if (tx.inputs_ptr()->empty())
                return aux_unsupported(id, "zero-input transaction: libbitcoin reads 00 as an input count unless the flag is 01");
            return {{"id", id}, {"ok", true},
                {"txid", encode_base16(tx.hash(false))},
                {"wtxid", encode_base16(tx.hash(true))},
                {"weight", tx.weight()},
                {"hex", encode_base16(tx.to_data(true))}};
        }

        const auto kind = req.at("kind").get<std::string>();
        const auto index = req.at("input_index").get<uint32_t>();
        const auto hash_type = req.at("hash_type").get<uint32_t>();
        const auto& inputs = *tx.inputs_ptr();
        if (index >= inputs.size())
            return aux_fail(id, "input index out of range");
        if (tx.is_coinbase())
            return aux_unsupported(id, "signature_hash asserts the transaction is not a coinbase");
        if (hash_type > 0xff)
            return aux_unsupported(id, "signature_hash takes a one-byte hash type");
        data_chunk script_bytes;
        if (!decode_base16(script_bytes, req.value("script_hex", std::string{})))
            return aux_fail(id, "script_hex is not valid hex");

        const auto it = inputs.begin() + index;
        const auto flag = static_cast<uint8_t>(hash_type);
        hash_digest digest{};
        uint32_t rules = chain::flags::bip16_rule;
        chain::script_version version = chain::script_version::unversioned;
        chain::script subscript{};
        uint64_t value = 0;
        hash_cptr tapleaf{};

        if (kind == "legacy")
        {
            subscript = chain::script{ strip_codeseparators(script_bytes), false };
        }
        else if (kind == "bip143")
        {
            subscript = chain::script{ script_bytes, false };
            value = req.at("amount_sats").get<uint64_t>();
            version = chain::script_version::segwit;
            rules |= chain::flags::bip141_rule | chain::flags::bip143_rule;
        }
        else if (kind == "bip341")
        {
            if (!(flag <= 0x03 || (flag >= 0x81 && flag <= 0x83)))
                return aux_fail(id, "undefined taproot hash type");
            const auto& prevouts = req.at("prevouts");
            if (prevouts.size() != inputs.size())
                return aux_fail(id, "prevout count does not match inputs");
            for (size_t i = 0; i < inputs.size(); ++i)
            {
                data_chunk spk;
                if (!decode_base16(spk, prevouts[i].at("script_pubkey_hex").get<std::string>()))
                    return aux_fail(id, "bad prevout");
                inputs[i]->prevout = to_shared(chain::output{
                    prevouts[i].at("amount_sats").get<uint64_t>(), chain::script{ spk, false } });
            }
            // libbitcoin reads the annex from the input's own witness and the code separator
            // position from interpreter state, so only requests that agree with those compare.
            const auto& stack = inputs[index]->witness().stack();
            data_chunk witness_annex;
            if (stack.size() >= 2 && !stack.back()->empty() && stack.back()->front() == 0x50)
                witness_annex = *stack.back();
            data_chunk req_annex;
            if (req.contains("annex_hex") && !req["annex_hex"].is_null() &&
                !decode_base16(req_annex, req["annex_hex"].get<std::string>()))
                return aux_fail(id, "annex_hex is not valid hex");
            if (req_annex != witness_annex)
                return aux_unsupported(id, "annex is read from the input witness, which differs from annex_hex");
            if (req.value("codesep_pos", uint64_t{0xffffffff}) != 0xffffffff)
                return aux_unsupported(id, "code separator position comes from interpreter state");
            if (req.contains("leaf_hash_hex") && !req["leaf_hash_hex"].is_null())
            {
                hash_digest leaf{};
                if (!decode_base16(leaf, req["leaf_hash_hex"].get<std::string>()))
                    return aux_fail(id, "leaf_hash_hex is not 32 bytes of hex");
                tapleaf = std::make_shared<const hash_digest>(leaf);
                subscript = chain::script{ script_bytes, false };
            }
            // The ANYONECANPAY serialization takes the spent amount from this parameter (as in
            // libbitcoin's own BIP341 tests), not from the prevout.
            value = prevouts[index].at("amount_sats").get<uint64_t>();
            version = chain::script_version::taproot;
            rules |= chain::flags::bip341_rule | chain::flags::bip342_rule;
        }
        else
        {
            return aux_unsupported(id, "unknown sighash kind " + kind);
        }
        if (kind != "bip341" && !subscript.is_valid())
            return aux_unsupported(id, "script does not parse; libbitcoin hashes parsed scripts");
        if (!tx.signature_hash(digest, it, subscript, value, tapleaf, version, flag, rules))
            return aux_fail(id, "no signature hash defined");
        return {{"id", id}, {"ok", true}, {"digest", encode_base16(digest)}};
    }
    catch (const std::exception& e)
    {
        return aux_fail(id, std::string("CRASH: exception: ") + e.what());
    }
}

static njson handle(const std::string& line)
{
    njson req;
    try
    {
        req = njson::parse(line);
    }
    catch (const std::exception& e)
    {
        return respond(0, false, "DESERIALIZE", std::string("bad request: ") + e.what());
    }
    const uint64_t id = req.value("id", uint64_t{0});
    if (req.contains("op"))
        return handle_aux(id, req);
    try
    {
        uint32_t rules = chain::flags::no_rules;
        for (const auto& f : req.at("flags"))
            if (!map_flag(f.get<std::string>(), rules))
                return respond(id, false, "INVALID_FLAGS",
                    "policy flag " + f.get<std::string>() + " unsupported");

        data_chunk raw;
        if (!decode_base16(raw, req.at("tx_hex").get<std::string>()))
            return respond(id, false, "DESERIALIZE", "tx_hex is not valid hex");
        const chain::transaction tx(raw, true);
        if (!tx.is_valid() || tx.serialized_size(true) != raw.size())
            return respond(id, false, "DESERIALIZE", "transaction does not decode exactly");

        const auto& prevouts = req.at("prevouts");
        const auto index = req.at("input_index").get<uint32_t>();
        const auto& inputs = *tx.inputs_ptr();
        if (index >= inputs.size())
            return respond(id, false, "TX_INDEX", "input_index out of range");
        if (prevouts.size() != inputs.size())
            return respond(id, false, "DESERIALIZE", "prevout count does not match inputs");

        for (size_t i = 0; i < inputs.size(); ++i)
        {
            data_chunk script;
            if (!decode_base16(script, prevouts[i].at("script_pubkey_hex").get<std::string>()))
                return respond(id, false, "DESERIALIZE", "prevout script is not valid hex");
            const auto amount = prevouts[i].at("amount_sats").get<uint64_t>();
            inputs[i]->prevout = to_shared(chain::output{amount, chain::script{script, false}});
        }

        // libbitcoin rejects a non-empty witness on a non-witness-program spend even when
        // segwit is not active (interpreter_connect.ipp, error::unexpected_witness); Core ignores
        // the witness without WITNESS. No such transaction can exist on chain (no witness
        // serialization before segwit, flag always on after), so abstain.
        if ((rules & chain::flags::bip141_rule) == 0 &&
            !inputs[index]->witness().stack().empty())
            return respond(id, false, "UNSUPPORTED",
                "witness data without WITNESS: libbitcoin rejects, Core ignores");

        chain::context ctx{};
        ctx.flags = rules;
        const code ec = machine::interpreter<machine::contiguous_stack>::connect(ctx, tx, index);
        if (ec == error::script_success)
            return respond(id, true, "", "");
        return respond(id, false, "UNKNOWN", ec.message());
    }
    catch (const std::exception& e)
    {
        return respond(id, false, "CRASH", std::string("exception: ") + e.what());
    }
}

int main()
{
    std::ios::sync_with_stdio(false);
    std::string line;
    while (std::getline(std::cin, line))
    {
        if (line.find_first_not_of(" \t\r") == std::string::npos)
            continue;
        std::cout << handle(line).dump() << '\n' << std::flush;
    }
    return 0;
}
