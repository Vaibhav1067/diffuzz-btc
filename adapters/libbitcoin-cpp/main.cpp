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
    {
        return {{"id", id}, {"ok", false}, {"unsupported", true},
            {"error", "libbitcoin adapter implements no auxiliary operations"}};
    }
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
