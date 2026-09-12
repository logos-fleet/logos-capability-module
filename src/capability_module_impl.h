#pragma once

// ─────────────────────────────────────────────────────────────────────────────
// capability_module — the trust root, as an ordinary universal module.
//
// It mints per-(caller, target) auth tokens and pushes them to the target, and
// it holds the access policy core registers. That needs two privileges no other
// module has: enumerating the token store, and delivering a token to an
// arbitrary module. It declares them in metadata.json:
//
//     "host_services": ["token_registry", "token_delivery"]
//
// and the HOST grants them, bound to this module's verified name. Ungranted,
// every gated call fails closed — and note that is not a partial degradation:
// looking up the target token reads the token registry, so an ungranted
// capability_module refuses EVERY requestModule.
//
// No Qt: this is a plain C++ class the generator turns into a module. The Qt
// plugin it used to be reached TokenManager directly, which is exactly the
// ambient privilege the host-services grant replaces.
//
// NO trailing `// comments` on declaration lines (the parser needs a `;`).
// ─────────────────────────────────────────────────────────────────────────────

#include <map>
#include <mutex>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <logos_json.h>
#include <logos_module_context.h>

class CapabilityModuleImpl : public LogosModuleContext {
public:
    CapabilityModuleImpl() = default;
    ~CapabilityModuleImpl() = default;

    // Mint a token letting the RPC caller (logos::currentCaller) call
    // `moduleName`, push it to the target, and return it. `fromModuleName` is
    // leftover ABI and is not used for identity. Empty string on any refusal —
    // unnamed caller, unknown target, policy denial, or an unreachable target.
    std::string requestModule(const std::string& fromModuleName,
                              const std::string& moduleName);

    // Restrict `targetModule` to `allowedCallers`. Only core (or this module)
    // may call this; the check is a constant-time comparison against their
    // tokens. Re-registering a target replaces its previous set.
    bool registerRestriction(const std::string& authToken,
                             const std::string& targetModule,
                             const std::vector<std::string>& allowedCallers);

    // ── Per-module consent (App Store guideline 4.7.3) ──────────────────────
    //
    // A Store shell installs modules at runtime, and the user is entitled to be
    // asked before one of them reaches another module's data. The gate belongs
    // here because requestModule is the one place EVERY cross-module authority
    // is minted: a gate anywhere else is a gate a module can route around.
    //
    // It fires only when one of the two parties is Downloaded. A core that
    // declares no origins — every desktop core today — sees no change at all.

    // Tell this module where `moduleName` came from. `origin` is "bundled"
    // (the app image shipped it) or "downloaded" (the user installed it from
    // the catalog at runtime). A module nobody declared counts as bundled.
    //
    // Trusted channel only, like registerRestriction: a module able to relabel
    // itself would exempt itself from the gate. Origins are NOT persisted —
    // the host re-declares them every boot from what it actually loaded, which
    // is the only authority on the question.
    //
    // Returns { success, error? }.
    LogosMap setModuleOrigin(const std::string& authToken, const std::string& moduleName, const std::string& origin);

    // [{ module, origin }] for everything the host declared, name-ordered.
    LogosList listModuleOrigins();

    // Where one ORDERED pair stands. `state` is one of:
    //   "not-required"  neither party is Downloaded; the gate is not on this path
    //   "granted"       the user allowed it; remembered and persisted
    //   "denied"        the user refused it; remembered and persisted
    //   "pending"       required, undecided, and the Shell has been asked
    //   "unknown"       required and undecided, and nothing has asked yet
    //
    // This is also where a refusal's REASON is readable. requestModule can only
    // answer with a token or with nothing, so a caller that wants to tell the
    // user why has to come here.
    //
    // Returns { caller, target, callerOrigin, targetOrigin, state, reason }.
    LogosMap consentStatus(const std::string& callerModule, const std::string& targetModule);

    // Record the user's answer for one ordered pair and persist it. Trusted
    // channel only — the module under the gate must not be able to pass itself
    // through it. Emits consentDecided. Returns { success, error? }.
    LogosMap decideConsent(const std::string& authToken, const std::string& callerModule, const std::string& targetModule, bool granted);

    // Return a pair to undecided, so the next call prompts again. The Shell's
    // "revoke" affordance. Trusted channel only. Returns { success, error? }.
    LogosMap forgetConsent(const std::string& authToken, const std::string& callerModule, const std::string& targetModule);

    // [{ caller, target, granted }] for every remembered decision. What the
    // Shell's privacy screen lists.
    LogosList listConsents();

    // consentRequired fires when a call needs a decision nobody has made. The
    // payload is { caller, target, callerOrigin, targetOrigin } and the Shell
    // answers with decideConsent.
    //
    // Fired ONCE per undecided pair, not once per attempt: a refused caller
    // retries (the SDK caches nothing on failure) and a prompt per retry would
    // bury the Shell. forgetConsent re-arms it.
    //
    // consentDecided fires on every decideConsent, payload
    // { caller, target, granted }, so a second surface (a settings list, the
    // module itself) can follow a decision it did not make.
logos_events:
    void consentRequired(const std::string& payload);
    void consentDecided(const std::string& payload);

protected:
    // Loads the persisted decisions. The gate works without a persistence path
    // (a directly-constructed impl, a host that provisions none) — it just
    // cannot remember across a restart.
    void onContextReady() override;

private:
    // Ordered (caller, target). Ordered because granting a Downloaded module
    // outbound access to chat must not also grant chat a way back into it.
    using Pair = std::pair<std::string, std::string>;

    enum class Origin { Bundled, Downloaded };

    // Is the trusted core/capability_module channel presenting this token?
    // Constant-time, and shared by every mutator below.
    bool isTrustedChannel(const std::string& authToken) const;

    Origin originOf(const std::string& moduleName) const;
    static const char* originName(Origin o);

    // The gate itself, called from requestModule with m_mutex NOT held.
    // Returns true to let the request through. Emits consentRequired on the
    // first refusal of an undecided pair.
    bool consentAllows(const std::string& callerName, const std::string& targetName);

    std::string consentFilePath() const;
    void loadConsents();
    void saveConsentsLocked() const;

private:
    // target -> callers permitted to reach it. A target absent from the map is
    // unrestricted; see the fail-open note in the .cpp.
    //
    // Guarded because a universal module may be dispatched concurrently if it
    // ever declares concurrency:"multi", and because this is policy state — the
    // Qt original was implicitly serialised by the event loop, which is not a
    // property to inherit silently.
    std::map<std::string, std::set<std::string>> m_restrictions;

    // What the host said about each module. Absent means Bundled.
    std::map<std::string, Origin> m_origins;

    // The remembered decisions, persisted. Only decided pairs live here.
    std::map<Pair, bool> m_consents;

    // Pairs the Shell has already been asked about in THIS process run. Not
    // persisted: a pair the user never answered must prompt again next launch
    // rather than come back as a silent refusal.
    std::set<Pair> m_announced;

    mutable std::mutex m_mutex;
};
