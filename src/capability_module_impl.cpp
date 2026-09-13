#include "capability_module_impl.h"

#include "uuid.h"

#include <logos_caller.h>
#include <logos_host_services.h>
#include <logos_protocol.h>

#include <cstdio>
#include <fstream>
#include <sstream>

namespace {

// The minted value IS the auth token, so this is the one place entropy matters.
// src/uuid.h draws from the platform CSPRNG and never from std::random_device,
// which the standard permits to be DETERMINISTIC and which historically was on
// MinGW — a live target here. It used to be boost::uuids::random_generator,
// which is the same guarantee; boost had to go because it was never a declared
// dependency of this module (it arrived through the Qt plugin backend's
// propagated inputs) and a BARE build links no Qt.
std::string mintToken()
{
    return logos_capability::uuidV4();
}

// RAII for the per-target client. lp_client_destroy is safe from any thread and
// defers teardown to the owner thread when needed, so an early return cannot
// leak the handle.
class ClientHandle {
public:
    ClientHandle(const std::string& target, const std::string& origin)
        : m_c(lp_client_create(target.c_str(), origin.c_str(), nullptr, nullptr)) {}
    ~ClientHandle() { if (m_c) lp_client_destroy(m_c); }
    ClientHandle(const ClientHandle&) = delete;
    ClientHandle& operator=(const ClientHandle&) = delete;

    lp_client* get() const { return m_c; }
    explicit operator bool() const { return m_c != nullptr; }

private:
    lp_client* m_c = nullptr;
};

void warn(const char* fmt, const std::string& a, const std::string& b = {})
{
    std::fprintf(stderr, fmt, a.c_str(), b.c_str());
}

// A module that calls out from its own initializer has not published its
// source yet, so this one grant can be unsatisfiable. Waiting the protocol
// default (20s) there would blow every startup deadline downstream — the
// standalone app gives a ui-host 10s to report ready — and turn one
// unreachable module into a dead UI. Fail fast instead: the caller gets no
// token and a clear reason, and the rest of startup keeps moving.
constexpr int kTokenPushTimeoutMs = 3000;

// The persisted decisions live in one small file in the host's per-instance
// directory. Named, not inlined, because the file IS the contract between two
// launches of the app.
constexpr const char* kConsentFileName = "consents.json";
constexpr int kConsentFileVersion = 1;

} // namespace

std::string CapabilityModuleImpl::requestModule(const std::string& fromModuleName,
                                                const std::string& moduleName)
{
    // Target emptiness is checked first so a missing name cannot be papered
    // over by a well-formed caller identity (or vice versa).
    if (moduleName.empty()) {
        warn("[capability_module] rejecting empty target module name (from='%s')\n",
             fromModuleName);
        return {};
    }

    // Identity comes from the RPC caller document the host pushed into this
    // image (logos_module_set_call_caller / logos::currentCaller), not from
    // `fromModuleName`. That argument is leftover ABI: any loaded allowlisted
    // name could be written there by the caller. Host maps to "core" (rule 5:
    // the host arm carries no name). Unnamed / unknown / derived / operator
    // refuse — those are not module identities this method can mint for.
    const logos::LogosCaller caller = logos::currentCaller();
    std::string callerName;
    if (caller.isHost()) {
        callerName = "core";
    } else if (caller.isModule() && !caller.name.empty()) {
        callerName = caller.name;
    } else {
        warn("[capability_module] rejecting request for '%s': no named caller on "
             "this dispatch (fromModuleName='%s')\n",
             moduleName, fromModuleName);
        return {};
    }
    if (!fromModuleName.empty() && fromModuleName != callerName) {
        warn("[capability_module] ignoring leftover fromModuleName='%s' "
             "(token-bound caller is '%s')\n",
             fromModuleName, callerName);
    }

    // token_registry remains load-bearing: tokenFor() below reads the registry,
    // and an ungranted image must fail closed rather than looking like "the
    // target is not loaded". The explicit status check (not empty()) is what
    // distinguishes those two refusals.
    logos::host::Status keysStatus;
    (void)logos::host::tokenKeys(&keysStatus);
    if (keysStatus.ungranted()) {
        warn("[capability_module] REFUSING '%s': this module was not granted the "
             "token_registry host service, so it cannot look up the target\n",
             callerName);
        return {};
    }

    // Known-target gate: no token for the target means it is not loaded. Don't
    // hand back a token the target would reject anyway.
    const std::string moduleToken = logos::host::tokenFor(moduleName);
    if (moduleToken.empty()) {
        warn("[capability_module] rejecting request for unknown target '%s' "
             "- no token registered for it\n", moduleName);
        return {};
    }

    // Access-policy gate.
    //
    // TODO(access-policy): still fail-OPEN — a target with no registered
    // restriction is unrestricted. Intentional for back-compat during rollout;
    // the end state is deny-by-default once every deployment ships a policy.
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_restrictions.find(moduleName);
        if (it != m_restrictions.end() && it->second.count(callerName) == 0) {
            warn("[capability_module] access policy denies '%s' -> '%s'\n",
                 callerName, moduleName);
            return {};
        }
    }

    // Per-module consent gate (guideline 4.7.3).
    //
    // LAST of the three gates, and that ordering is deliberate: a prompt is a
    // user-visible act, so it is only ever spent on a request that would
    // otherwise have succeeded. An unknown target and a deployment restriction
    // both refuse ABOVE this line, and neither one is the user's to answer.
    if (!consentAllows(callerName, moduleName))
        return {};

    const std::string authToken = mintToken();

    ClientHandle client(moduleName, "capability_module");
    if (!client) {
        warn("[capability_module] could not create a client for target '%s'\n", moduleName);
        return {};
    }

    // Deliver the token for the REQUESTER to the TARGET.
    //
    // The argument order is the trap here, so spell it out: authenticate with
    // the TARGET's own token, `originModule` is the TARGET (the module being
    // told), and `moduleName` is the REQUESTER (the module the token is FOR).
    // Swapping the last two still compiles and still returns an ok-shaped
    // status; it just tells the wrong module about the wrong token.
    const logos::host::Status pushed = logos::host::informModuleTokenTo(
        client.get(),
        /*authToken=*/moduleToken,
        /*originModule=*/moduleName,
        /*moduleName=*/callerName,
        /*token=*/authToken,
        kTokenPushTimeoutMs);

    if (!pushed) {
        if (pushed.ungranted()) {
            warn("[capability_module] REFUSING '%s': this module was not granted the "
                 "token_delivery host service, so it cannot push tokens\n", moduleName);
        } else {
            warn("[capability_module] failed to inform '%s' about the token for '%s'\n",
                 moduleName, callerName);
        }
        return {};
    }

    return authToken;
}

bool CapabilityModuleImpl::registerRestriction(const std::string& authToken,
                                               const std::string& targetModule,
                                               const std::vector<std::string>& allowedCallers)
{
    // Trusted-channel gate: only core (or this module) may rewrite the policy.
    // Both hold this module's auth token; a peer knows only its own. The
    // generic authorization that fronts this method accepts ANY issued token,
    // which would otherwise let any module rewrite the policy.
    //
    // constantTimeEquals, not ==: comparing a secret with == leaks the length
    // of the matching prefix through timing.
    if (!isTrustedChannel(authToken)) {
        warn("[capability_module] rejecting restriction for '%s' - caller is not the "
             "trusted core channel\n", targetModule);
        return false;
    }

    if (targetModule.empty()) {
        warn("[capability_module] rejecting empty target module%s\n", std::string());
        return false;
    }

    // Overwrite any previous restriction — core is the single source of truth
    // and re-registers the full set each boot.
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_restrictions[targetModule] =
            std::set<std::string>(allowedCallers.begin(), allowedCallers.end());
    }
    return true;
}


// ─────────────────────────────────────────────────────────────────────────────
// Per-module consent (guideline 4.7.3)
//
// The gate itself is eleven lines inside requestModule. Everything below is the
// bookkeeping around it: who is Downloaded, what the user answered, and how that
// answer survives the app being killed.
//
// Two things are deliberately NOT here. There is no waiting: capability_module
// is on the dispatch path of every cross-module call, so blocking one on a
// dialog would hold a module thread for as long as the user takes to read it.
// And there is no UI: this module cannot draw, so the refusal happens now and
// the prompt is an event the Shell answers later, with the caller's retry
// carrying the decision.
// ─────────────────────────────────────────────────────────────────────────────

bool CapabilityModuleImpl::isTrustedChannel(const std::string& authToken) const
{
    // Only core (or this module) holds these; a peer knows only its own token.
    // constantTimeEquals, not ==: comparing a secret with == leaks the length of
    // the matching prefix through timing.
    if (authToken.empty())
        return false;
    const std::string coreToken = logos::host::tokenFor("core");
    const std::string capToken  = logos::host::tokenFor("capability_module");
    return (!coreToken.empty() && logos::host::constantTimeEquals(authToken, coreToken))
        || (!capToken.empty()  && logos::host::constantTimeEquals(authToken, capToken));
}

const char* CapabilityModuleImpl::originName(Origin o)
{
    return o == Origin::Downloaded ? "downloaded" : "bundled";
}

CapabilityModuleImpl::Origin CapabilityModuleImpl::originOf(const std::string& moduleName) const
{
    // Undeclared means Bundled, and that default is what keeps this change off
    // the path of every core that has no Downloaded modules: a desktop host
    // declares nothing, so every pair is Bundled/Bundled and the gate is not on
    // the path at all.
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_origins.find(moduleName);
    return it == m_origins.end() ? Origin::Bundled : it->second;
}

LogosMap CapabilityModuleImpl::setModuleOrigin(const std::string& authToken,
                                               const std::string& moduleName,
                                               const std::string& origin)
{
    if (!isTrustedChannel(authToken)) {
        warn("[capability_module] rejecting origin for '%s' - caller is not the "
             "trusted core channel\n", moduleName);
        return LogosMap{{"success", false},
                        {"error", "only the trusted core channel may declare a module's origin"}};
    }
    if (moduleName.empty())
        return LogosMap{{"success", false}, {"error", "empty module name"}};

    Origin parsed;
    if (origin == "bundled")         parsed = Origin::Bundled;
    else if (origin == "downloaded") parsed = Origin::Downloaded;
    else {
        // A typo must not silently read as Bundled, which is the exempt side.
        return LogosMap{{"success", false},
                        {"error", "unknown origin '" + origin +
                                  "': expected \"bundled\" or \"downloaded\""}};
    }

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_origins[moduleName] = parsed;
    }
    return LogosMap{{"success", true}};
}

LogosList CapabilityModuleImpl::listModuleOrigins()
{
    LogosList out = LogosList::array();
    std::lock_guard<std::mutex> lock(m_mutex);
    for (const auto& [name, origin] : m_origins)
        out.push_back(LogosMap{{"module", name}, {"origin", originName(origin)}});
    return out;
}

LogosMap CapabilityModuleImpl::consentStatus(const std::string& callerModule,
                                             const std::string& targetModule)
{
    const Origin callerOrigin = originOf(callerModule);
    const Origin targetOrigin = originOf(targetModule);

    LogosMap out{
        {"caller", callerModule},
        {"target", targetModule},
        {"callerOrigin", originName(callerOrigin)},
        {"targetOrigin", originName(targetOrigin)},
    };

    if (callerOrigin == Origin::Bundled && targetOrigin == Origin::Bundled) {
        out["state"]  = "not-required";
        out["reason"] = "both '" + callerModule + "' and '" + targetModule +
                        "' came with the app, so no per-module consent applies";
        return out;
    }

    std::lock_guard<std::mutex> lock(m_mutex);
    const Pair key{callerModule, targetModule};
    auto it = m_consents.find(key);
    if (it != m_consents.end()) {
        out["state"]  = it->second ? "granted" : "denied";
        out["reason"] = it->second
            ? ("you allowed '" + callerModule + "' to use '" + targetModule + "'")
            : ("you did not allow '" + callerModule + "' to use '" + targetModule +
               "', so its calls to it fail");
        return out;
    }

    out["state"]  = m_announced.count(key) ? "pending" : "unknown";
    out["reason"] = "'" + callerModule + "' wants to use '" + targetModule +
                    "' and you have not decided yet";
    return out;
}

bool CapabilityModuleImpl::consentAllows(const std::string& callerName,
                                         const std::string& targetName)
{
    const LogosMap status = consentStatus(callerName, targetName);
    const std::string state = status.value("state", std::string());

    if (state == "not-required" || state == "granted")
        return true;

    if (state == "denied") {
        warn("[capability_module] consent denies '%s' -> '%s'\n", callerName, targetName);
        return false;
    }

    // Undecided. Announce ONCE per pair and refuse. The caller's retry — which
    // the SDK does not cache a failure for — is what carries the decision once
    // the Shell has one; a prompt per retry would bury the user.
    bool announceNow = false;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        announceNow = m_announced.insert(Pair{callerName, targetName}).second;
    }
    if (announceNow) {
        consentRequired(LogosMap{
            {"caller", callerName},
            {"target", targetName},
            {"callerOrigin", status.value("callerOrigin", std::string("bundled"))},
            {"targetOrigin", status.value("targetOrigin", std::string("bundled"))},
        }.dump());
    }
    warn("[capability_module] '%s' needs consent to use '%s'; refusing until the "
         "user decides\n", callerName, targetName);
    return false;
}

LogosMap CapabilityModuleImpl::decideConsent(const std::string& authToken,
                                             const std::string& callerModule,
                                             const std::string& targetModule,
                                             bool granted)
{
    if (!isTrustedChannel(authToken)) {
        warn("[capability_module] rejecting a consent decision for '%s' - caller is "
             "not the trusted core channel\n", callerModule);
        return LogosMap{{"success", false},
                        {"error", "only the trusted core channel may record a consent decision"}};
    }
    if (callerModule.empty() || targetModule.empty())
        return LogosMap{{"success", false}, {"error", "both caller and target are required"}};

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_consents[Pair{callerModule, targetModule}] = granted;
        m_announced.erase(Pair{callerModule, targetModule});
        saveConsentsLocked();
    }
    consentDecided(LogosMap{
        {"caller", callerModule},
        {"target", targetModule},
        {"granted", granted},
    }.dump());
    return LogosMap{{"success", true}};
}

LogosMap CapabilityModuleImpl::forgetConsent(const std::string& authToken,
                                             const std::string& callerModule,
                                             const std::string& targetModule)
{
    if (!isTrustedChannel(authToken))
        return LogosMap{{"success", false},
                        {"error", "only the trusted core channel may forget a consent decision"}};

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_consents.erase(Pair{callerModule, targetModule});
        // The announcement is cleared too, so the next call prompts again —
        // which is the whole point of forgetting one.
        m_announced.erase(Pair{callerModule, targetModule});
        saveConsentsLocked();
    }
    return LogosMap{{"success", true}};
}

LogosList CapabilityModuleImpl::listConsents()
{
    LogosList out = LogosList::array();
    std::lock_guard<std::mutex> lock(m_mutex);
    for (const auto& [pair, granted] : m_consents)
        out.push_back(LogosMap{{"caller", pair.first},
                               {"target", pair.second},
                               {"granted", granted}});
    return out;
}

// ── persistence ─────────────────────────────────────────────────────────────

void CapabilityModuleImpl::onContextReady()
{
    loadConsents();
}

std::string CapabilityModuleImpl::consentFilePath() const
{
    const std::string& dir = instancePersistencePath();
    if (dir.empty())
        return {};
    return dir + "/" + kConsentFileName;
}

void CapabilityModuleImpl::loadConsents()
{
    const std::string path = consentFilePath();
    if (path.empty())
        return;

    std::ifstream in(path);
    if (!in)
        return;  // first launch: nothing decided yet, which is not an error

    std::stringstream buf;
    buf << in.rdbuf();

    // A record we cannot read is a record of nothing. Fail CLOSED on every pair
    // (no decision is restored, so each one prompts again) rather than refusing
    // to start — the alternative is a module that cannot load because a file it
    // owns got truncated.
    const LogosMap doc = LogosMap::parse(buf.str(), nullptr, /*allow_exceptions=*/false);
    if (doc.is_discarded() || !doc.is_object()) {
        warn("[capability_module] ignoring an unreadable consent record at '%s'; "
             "every pair will be asked about again\n", path);
        return;
    }
    if (doc.value("version", 0) != kConsentFileVersion) {
        warn("[capability_module] ignoring a consent record at '%s' written by a "
             "different version\n", path);
        return;
    }

    std::lock_guard<std::mutex> lock(m_mutex);
    for (const auto& e : doc.value("consents", LogosList::array())) {
        if (!e.is_object()) continue;
        const std::string caller = e.value("caller", std::string());
        const std::string target = e.value("target", std::string());
        if (caller.empty() || target.empty()) continue;
        m_consents[Pair{caller, target}] = e.value("granted", false);
    }
}

void CapabilityModuleImpl::saveConsentsLocked() const
{
    const std::string path = consentFilePath();
    if (path.empty())
        return;  // no host-provisioned directory: the gate works, it just forgets

    LogosList entries = LogosList::array();
    for (const auto& [pair, granted] : m_consents)
        entries.push_back(LogosMap{{"caller", pair.first},
                                   {"target", pair.second},
                                   {"granted", granted}});
    const LogosMap doc{{"version", kConsentFileVersion}, {"consents", entries}};

    // Write-then-rename: a kill between the truncate and the write of an
    // in-place update would lose every decision the user has ever made, and
    // "the app forgot what I allowed" is the one failure this file exists to
    // prevent.
    const std::string tmp = path + ".tmp";
    {
        std::ofstream out(tmp, std::ios::trunc);
        if (!out) {
            warn("[capability_module] could not write the consent record at '%s'\n", tmp);
            return;
        }
        out << doc.dump(2) << "\n";
        if (!out.good()) {
            warn("[capability_module] the consent record at '%s' did not write cleanly\n", tmp);
            return;
        }
    }
    if (std::rename(tmp.c_str(), path.c_str()) != 0)
        warn("[capability_module] could not move the consent record into place at '%s'\n", path);
}
