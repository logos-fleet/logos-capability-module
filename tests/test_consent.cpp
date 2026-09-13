// Per-module consent — the gate a Store shell needs and a desktop does not.
//
// App Store guideline 4.7.3 asks that the user be asked before data crosses to
// a module they installed at runtime. The Logos answer is that the gate lives
// where every cross-module authority already comes from: capability_module's
// requestModule. Nothing else in the platform is on that path for every caller,
// and a gate anywhere else would be one a module could route around.
//
// The rules this file pins:
//
//   * The gate fires only when ONE OF THE TWO PARTIES IS DOWNLOADED. A desktop
//     core declares no origins at all, so every pair is Bundled/Bundled and
//     requestModule behaves exactly as it did — that is what keeps this change
//     off the path of the thirty modules that were fine before it.
//   * A decision is REMEMBERED PER ORDERED PAIR, and it persists: the record
//     lives under the host's per-instance persistence directory, so a grant
//     survives the app being killed. Restarting is not a way to re-ask, and it
//     is not a way to escape a denial either.
//   * An undecided pair is REFUSED and ANNOUNCED. capability_module has no UI
//     and must never block a dispatch waiting for one — the call fails now, the
//     Shell prompts, and the module's next attempt is decided. `consentStatus`
//     is where the refusal's reason is readable, because requestModule's return
//     type is the token itself and has no room for one.
//
// Everything here drives the real article: the real host-services grant, the
// real token registry, and a real LogosMockSetup transport, exactly as
// test_capability_module.cpp does. The one thing these tests substitute is the
// EVENT SINK — logos_test::EventCapture, via the forwarders in
// capability_module_events_test.cpp — because the codegen-emitted production
// bodies marshal through a host callback that a direct-construction test has no
// way to install.

#include <logos_test.h>
#include <logos_mock.h>
#include <logos_protocol.h>

#include "capability_module_impl.h"

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>
#include <unistd.h>

namespace {

constexpr const char* kAllHostServices = R"(["token_registry","token_delivery"])";
constexpr const char* kNoHostServices  = "[]";

class ConsentFixture {
public:
    ConsentFixture() : m_grantRc(lp_grant_host_services(kAllHostServices)) {}
    ~ConsentFixture() { lp_grant_host_services(kNoHostServices); }
    ConsentFixture(const ConsentFixture&) = delete;
    ConsentFixture& operator=(const ConsentFixture&) = delete;
    int grantRc() const { return m_grantRc; }

private:
    LogosMockSetup m_mock;  // declared first: its ctor clears the token store
    int m_grantRc;
};

void seedModule(const std::string& name) {
    lp_token_save(name.c_str(), ("seed-token-" + name).c_str());
}

// The trusted core/capability_module channel, as in test_capability_module.cpp.
const std::string kTrustedToken = "seed-token-capability_module";
void seedTrustedChannel() { seedModule("capability_module"); }

// A per-test scratch directory that stands in for the host's per-instance
// persistence path. Removed on destruction so a consent file cannot leak into
// the next test — the records are keyed by module name, which repeats.
class ScratchDir {
public:
    ScratchDir() {
        char tmpl[] = "/tmp/logos-consent-testXXXXXX";
        const char* d = ::mkdtemp(tmpl);
        m_path = d ? d : "";
    }
    ~ScratchDir() {
        if (m_path.empty()) return;
        const std::string cmd = "rm -rf '" + m_path + "'";
        (void)std::system(cmd.c_str());
    }
    ScratchDir(const ScratchDir&) = delete;
    ScratchDir& operator=(const ScratchDir&) = delete;
    const std::string& path() const { return m_path; }

private:
    std::string m_path;
};

// Hand an impl the context the framework would, which is what populates
// instancePersistencePath() and fires onContextReady().
void giveContext(CapabilityModuleImpl& impl, const std::string& dir) {
    impl._logosCoreSetContext_(/*modulePath=*/"", /*instanceId=*/"test", dir);
}

std::string stateOf(CapabilityModuleImpl& impl, const std::string& caller,
                    const std::string& target) {
    const LogosMap status = impl.consentStatus(caller, target);
    return status.value("state", std::string());
}

}  // namespace

// ── The gate does not exist for a pair of Bundled modules ───────────────────

LOGOS_TEST(consent_is_not_required_between_bundled_modules) {
    ConsentFixture fixture;
    seedModule("chat_ui");
    seedModule("chat_module");

    CapabilityModuleImpl impl;

    LOGOS_ASSERT_EQ(stateOf(impl, "chat_ui", "chat_module"), std::string("not-required"));
}

LOGOS_TEST(requestModule_is_unaffected_when_no_origin_was_declared) {
    // The regression guard for every deployment that predates consent: a core
    // that declares no origins must mint exactly as before.
    ConsentFixture fixture;
    seedModule("requester");
    seedModule("target");
    logos_test::EventCapture events;

    CapabilityModuleImpl impl;
    const auto caller = logos::CallCaller::module("requester");

    LOGOS_ASSERT_FALSE(impl.requestModule("requester", "target").empty());
    LOGOS_ASSERT_FALSE(events.has("consentRequired"));
}

// ── Declaring an origin ─────────────────────────────────────────────────────

LOGOS_TEST(setModuleOrigin_requires_the_trusted_core_channel) {
    ConsentFixture fixture;
    seedTrustedChannel();
    seedModule("malicious_module");

    CapabilityModuleImpl impl;

    // A module presenting its OWN token must not be able to relabel itself (or
    // anyone else) as Bundled and so exempt itself from the gate.
    const LogosMap refused =
        impl.setModuleOrigin("seed-token-malicious_module", "malicious_module", "bundled");
    LOGOS_ASSERT_FALSE(refused.value("success", true));

    const LogosMap accepted = impl.setModuleOrigin(kTrustedToken, "malicious_module", "downloaded");
    LOGOS_ASSERT_TRUE(accepted.value("success", false));
}

LOGOS_TEST(setModuleOrigin_rejects_an_unknown_origin_word) {
    ConsentFixture fixture;
    seedTrustedChannel();

    CapabilityModuleImpl impl;

    const LogosMap refused = impl.setModuleOrigin(kTrustedToken, "some_module", "sideloaded");
    LOGOS_ASSERT_FALSE(refused.value("success", true));
    LOGOS_ASSERT_CONTAINS(refused.value("error", std::string()), "origin");
}

// ── An undecided pair is refused and announced ──────────────────────────────

LOGOS_TEST(requestModule_refuses_and_announces_an_undecided_downloaded_caller) {
    ConsentFixture fixture;
    seedTrustedChannel();
    seedModule("counter_ui");
    seedModule("chat_module");
    logos_test::EventCapture events;

    CapabilityModuleImpl impl;
    LOGOS_ASSERT_TRUE(
        impl.setModuleOrigin(kTrustedToken, "counter_ui", "downloaded").value("success", false));

    const auto caller = logos::CallCaller::module("counter_ui");
    const std::string token = impl.requestModule("counter_ui", "chat_module");

    LOGOS_ASSERT_TRUE(token.empty());
    LOGOS_ASSERT_EQ(stateOf(impl, "counter_ui", "chat_module"), std::string("pending"));

    const auto entry = events.waitFor("consentRequired", 0);
    LOGOS_ASSERT_EQ(entry.name, std::string("consentRequired"));
    const LogosMap payload = LogosMap::parse(entry.data);
    LOGOS_ASSERT_EQ(payload.value("caller", std::string()), std::string("counter_ui"));
    LOGOS_ASSERT_EQ(payload.value("target", std::string()), std::string("chat_module"));
    LOGOS_ASSERT_EQ(payload.value("callerOrigin", std::string()), std::string("downloaded"));
    LOGOS_ASSERT_EQ(payload.value("targetOrigin", std::string()), std::string("bundled"));
}

LOGOS_TEST(requestModule_announces_a_pending_pair_once_not_once_per_retry) {
    // A refused caller retries — the SDK caches nothing on failure — and a
    // prompt per retry would bury the Shell.
    ConsentFixture fixture;
    seedTrustedChannel();
    seedModule("counter_ui");
    seedModule("chat_module");
    logos_test::EventCapture events;

    CapabilityModuleImpl impl;
    impl.setModuleOrigin(kTrustedToken, "counter_ui", "downloaded");

    const auto caller = logos::CallCaller::module("counter_ui");
    for (int i = 0; i < 5; ++i)
        LOGOS_ASSERT_TRUE(impl.requestModule("counter_ui", "chat_module").empty());

    LOGOS_ASSERT_EQ(events.all("consentRequired").size(), std::size_t(1));
}

LOGOS_TEST(the_gate_also_fires_when_only_the_TARGET_is_downloaded) {
    // Data crosses in both directions: a Bundled module handing something to a
    // Downloaded one is the case 4.7.3 is actually about.
    ConsentFixture fixture;
    seedTrustedChannel();
    seedModule("chat_ui");
    seedModule("counter");
    logos_test::EventCapture events;

    CapabilityModuleImpl impl;
    impl.setModuleOrigin(kTrustedToken, "counter", "downloaded");

    const auto caller = logos::CallCaller::module("chat_ui");
    LOGOS_ASSERT_TRUE(impl.requestModule("chat_ui", "counter").empty());
    LOGOS_ASSERT_TRUE(events.has("consentRequired"));
}

// ── A decision decides ──────────────────────────────────────────────────────

LOGOS_TEST(a_granted_pair_mints_a_token) {
    ConsentFixture fixture;
    seedTrustedChannel();
    seedModule("counter_ui");
    seedModule("chat_module");
    logos_test::EventCapture events;

    CapabilityModuleImpl impl;
    impl.setModuleOrigin(kTrustedToken, "counter_ui", "downloaded");

    const LogosMap decided =
        impl.decideConsent(kTrustedToken, "counter_ui", "chat_module", true);
    LOGOS_ASSERT_TRUE(decided.value("success", false));
    LOGOS_ASSERT_TRUE(events.has("consentDecided"));

    const auto caller = logos::CallCaller::module("counter_ui");
    LOGOS_ASSERT_FALSE(impl.requestModule("counter_ui", "chat_module").empty());
    LOGOS_ASSERT_EQ(stateOf(impl, "counter_ui", "chat_module"), std::string("granted"));
}

LOGOS_TEST(a_denied_pair_is_refused_with_a_readable_reason) {
    ConsentFixture fixture;
    seedTrustedChannel();
    seedModule("counter_ui");
    seedModule("chat_module");

    CapabilityModuleImpl impl;
    impl.setModuleOrigin(kTrustedToken, "counter_ui", "downloaded");
    impl.decideConsent(kTrustedToken, "counter_ui", "chat_module", false);

    const auto caller = logos::CallCaller::module("counter_ui");
    LOGOS_ASSERT_TRUE(impl.requestModule("counter_ui", "chat_module").empty());

    const LogosMap status = impl.consentStatus("counter_ui", "chat_module");
    LOGOS_ASSERT_EQ(status.value("state", std::string()), std::string("denied"));
    // The Shell shows this string. requestModule can only answer with a token
    // or nothing, so a caller's "why" has to be readable here.
    LOGOS_ASSERT_CONTAINS(status.value("reason", std::string()), "counter_ui");
    LOGOS_ASSERT_CONTAINS(status.value("reason", std::string()), "chat_module");
}

LOGOS_TEST(a_decision_is_per_ordered_pair_and_not_per_module) {
    ConsentFixture fixture;
    seedTrustedChannel();
    seedModule("counter_ui");
    seedModule("chat_module");
    seedModule("wallet_module");

    CapabilityModuleImpl impl;
    impl.setModuleOrigin(kTrustedToken, "counter_ui", "downloaded");
    impl.decideConsent(kTrustedToken, "counter_ui", "chat_module", true);

    LOGOS_ASSERT_EQ(stateOf(impl, "counter_ui", "chat_module"), std::string("granted"));
    // Same caller, different target: undecided.
    LOGOS_ASSERT_EQ(stateOf(impl, "counter_ui", "wallet_module"), std::string("unknown"));
    // Reversed pair: also undecided. Granting outbound access does not grant
    // the other module a way back in.
    LOGOS_ASSERT_EQ(stateOf(impl, "chat_module", "counter_ui"), std::string("unknown"));
}

LOGOS_TEST(decideConsent_requires_the_trusted_core_channel) {
    ConsentFixture fixture;
    seedTrustedChannel();
    seedModule("counter_ui");
    seedModule("chat_module");

    CapabilityModuleImpl impl;
    impl.setModuleOrigin(kTrustedToken, "counter_ui", "downloaded");

    // The module under the gate must not be able to grant itself through it.
    const LogosMap refused =
        impl.decideConsent("seed-token-counter_ui", "counter_ui", "chat_module", true);
    LOGOS_ASSERT_FALSE(refused.value("success", true));
    LOGOS_ASSERT_EQ(stateOf(impl, "counter_ui", "chat_module"), std::string("unknown"));
}

LOGOS_TEST(forgetConsent_returns_a_pair_to_undecided_and_re_announces) {
    ConsentFixture fixture;
    seedTrustedChannel();
    seedModule("counter_ui");
    seedModule("chat_module");
    logos_test::EventCapture events;

    CapabilityModuleImpl impl;
    impl.setModuleOrigin(kTrustedToken, "counter_ui", "downloaded");
    impl.decideConsent(kTrustedToken, "counter_ui", "chat_module", true);

    LOGOS_ASSERT_TRUE(
        impl.forgetConsent(kTrustedToken, "counter_ui", "chat_module").value("success", false));
    LOGOS_ASSERT_EQ(stateOf(impl, "counter_ui", "chat_module"), std::string("unknown"));

    const auto caller = logos::CallCaller::module("counter_ui");
    LOGOS_ASSERT_TRUE(impl.requestModule("counter_ui", "chat_module").empty());
    LOGOS_ASSERT_EQ(events.all("consentRequired").size(), std::size_t(1));
}

LOGOS_TEST(listConsents_reports_every_decision) {
    ConsentFixture fixture;
    seedTrustedChannel();

    CapabilityModuleImpl impl;
    impl.decideConsent(kTrustedToken, "counter_ui", "chat_module", true);
    impl.decideConsent(kTrustedToken, "counter_ui", "wallet_module", false);

    const LogosList all = impl.listConsents();
    LOGOS_ASSERT_EQ(all.size(), std::size_t(2));
    bool sawGrant = false, sawDenial = false;
    for (const auto& e : all) {
        if (e.value("target", std::string()) == "chat_module")
            sawGrant = e.value("granted", false);
        if (e.value("target", std::string()) == "wallet_module")
            sawDenial = !e.value("granted", true);
    }
    LOGOS_ASSERT_TRUE(sawGrant);
    LOGOS_ASSERT_TRUE(sawDenial);
}

// ── The decision survives a restart ─────────────────────────────────────────

LOGOS_TEST(a_grant_survives_a_restart) {
    ConsentFixture fixture;
    seedTrustedChannel();
    seedModule("counter_ui");
    seedModule("chat_module");
    ScratchDir scratch;
    LOGOS_ASSERT_FALSE(scratch.path().empty());

    {
        CapabilityModuleImpl first;
        giveContext(first, scratch.path());
        first.setModuleOrigin(kTrustedToken, "counter_ui", "downloaded");
        LOGOS_ASSERT_TRUE(
            first.decideConsent(kTrustedToken, "counter_ui", "chat_module", true)
                .value("success", false));
    }

    // A second instance over the same persistence directory IS the restart: the
    // host hands the same path back, and nothing else carries over.
    CapabilityModuleImpl second;
    giveContext(second, scratch.path());
    second.setModuleOrigin(kTrustedToken, "counter_ui", "downloaded");

    LOGOS_ASSERT_EQ(stateOf(second, "counter_ui", "chat_module"), std::string("granted"));

    const auto caller = logos::CallCaller::module("counter_ui");
    LOGOS_ASSERT_FALSE(second.requestModule("counter_ui", "chat_module").empty());
}

LOGOS_TEST(a_denial_survives_a_restart_too) {
    // Restarting the app is not a way to escape a denial.
    ConsentFixture fixture;
    seedTrustedChannel();
    seedModule("counter_ui");
    seedModule("chat_module");
    ScratchDir scratch;

    {
        CapabilityModuleImpl first;
        giveContext(first, scratch.path());
        first.decideConsent(kTrustedToken, "counter_ui", "chat_module", false);
    }

    CapabilityModuleImpl second;
    giveContext(second, scratch.path());
    second.setModuleOrigin(kTrustedToken, "counter_ui", "downloaded");

    LOGOS_ASSERT_EQ(stateOf(second, "counter_ui", "chat_module"), std::string("denied"));
    const auto caller = logos::CallCaller::module("counter_ui");
    LOGOS_ASSERT_TRUE(second.requestModule("counter_ui", "chat_module").empty());
}

LOGOS_TEST(a_pending_pair_does_not_persist) {
    // Only DECISIONS are written. A pair the user never answered must come back
    // as undecided and prompt again, not come back as a silent refusal.
    ConsentFixture fixture;
    seedTrustedChannel();
    seedModule("counter_ui");
    seedModule("chat_module");
    ScratchDir scratch;

    {
        logos_test::EventCapture events;
        CapabilityModuleImpl first;
        giveContext(first, scratch.path());
        first.setModuleOrigin(kTrustedToken, "counter_ui", "downloaded");
        const auto caller = logos::CallCaller::module("counter_ui");
        first.requestModule("counter_ui", "chat_module");
        LOGOS_ASSERT_TRUE(events.has("consentRequired"));
    }

    logos_test::EventCapture events;
    CapabilityModuleImpl second;
    giveContext(second, scratch.path());
    second.setModuleOrigin(kTrustedToken, "counter_ui", "downloaded");

    LOGOS_ASSERT_EQ(stateOf(second, "counter_ui", "chat_module"), std::string("unknown"));
    const auto caller = logos::CallCaller::module("counter_ui");
    second.requestModule("counter_ui", "chat_module");
    LOGOS_ASSERT_TRUE(events.has("consentRequired"));
}

LOGOS_TEST(no_persistence_path_means_no_file_and_no_crash) {
    // Unit tests, the lgpd-style direct construction, and any host that does
    // not provision persistence all land here. The gate must still WORK for the
    // life of the process; it just cannot remember.
    ConsentFixture fixture;
    seedTrustedChannel();
    seedModule("counter_ui");
    seedModule("chat_module");

    CapabilityModuleImpl impl;  // no giveContext: instancePersistencePath() is ""
    impl.setModuleOrigin(kTrustedToken, "counter_ui", "downloaded");
    LOGOS_ASSERT_TRUE(
        impl.decideConsent(kTrustedToken, "counter_ui", "chat_module", true)
            .value("success", false));

    const auto caller = logos::CallCaller::module("counter_ui");
    LOGOS_ASSERT_FALSE(impl.requestModule("counter_ui", "chat_module").empty());
}

LOGOS_TEST(a_corrupt_consent_file_is_ignored_rather_than_fatal) {
    ConsentFixture fixture;
    seedTrustedChannel();
    seedModule("counter_ui");
    seedModule("chat_module");
    ScratchDir scratch;

    {
        std::ofstream out(scratch.path() + "/consents.json");
        out << "{ this is not json";
    }

    CapabilityModuleImpl impl;
    giveContext(impl, scratch.path());
    impl.setModuleOrigin(kTrustedToken, "counter_ui", "downloaded");

    // Fail CLOSED on the pair, not fail to start: an unreadable record means
    // nothing was decided.
    LOGOS_ASSERT_EQ(stateOf(impl, "counter_ui", "chat_module"), std::string("unknown"));
    LOGOS_ASSERT_TRUE(
        impl.decideConsent(kTrustedToken, "counter_ui", "chat_module", true)
            .value("success", false));
    LOGOS_ASSERT_EQ(stateOf(impl, "counter_ui", "chat_module"), std::string("granted"));
}

// ── The gate is downstream of the ones that were already there ──────────────

LOGOS_TEST(a_granted_pair_is_still_refused_by_the_access_policy) {
    // Consent is the USER's answer; registerRestriction is the DEPLOYMENT's.
    // Neither overrides the other, and the stricter one wins.
    ConsentFixture fixture;
    seedTrustedChannel();
    seedModule("counter_ui");
    seedModule("chat_module");

    CapabilityModuleImpl impl;
    impl.setModuleOrigin(kTrustedToken, "counter_ui", "downloaded");
    impl.decideConsent(kTrustedToken, "counter_ui", "chat_module", true);
    LOGOS_ASSERT_TRUE(impl.registerRestriction(kTrustedToken, "chat_module", {"chat_ui"}));

    const auto caller = logos::CallCaller::module("counter_ui");
    LOGOS_ASSERT_TRUE(impl.requestModule("counter_ui", "chat_module").empty());
}

LOGOS_TEST(an_unknown_target_is_refused_before_anyone_is_prompted) {
    // The prompt is a user-visible act; spending one on a target that is not
    // even loaded would train the user to dismiss them.
    ConsentFixture fixture;
    seedTrustedChannel();
    seedModule("counter_ui");
    logos_test::EventCapture events;

    CapabilityModuleImpl impl;
    impl.setModuleOrigin(kTrustedToken, "counter_ui", "downloaded");

    const auto caller = logos::CallCaller::module("counter_ui");
    LOGOS_ASSERT_TRUE(impl.requestModule("counter_ui", "never_loaded").empty());
    LOGOS_ASSERT_FALSE(events.has("consentRequired"));
}

LOGOS_TEST(listModuleOrigins_reports_what_the_host_declared) {
    ConsentFixture fixture;
    seedTrustedChannel();

    CapabilityModuleImpl impl;
    impl.setModuleOrigin(kTrustedToken, "counter_ui", "downloaded");
    impl.setModuleOrigin(kTrustedToken, "chat_module", "bundled");

    const LogosList origins = impl.listModuleOrigins();
    LOGOS_ASSERT_EQ(origins.size(), std::size_t(2));
}
