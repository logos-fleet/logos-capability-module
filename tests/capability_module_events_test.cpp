// Qt-free test bodies for CapabilityModuleImpl's `logos_events:` methods.
//
// Production bodies are codegen-emitted in capability_module_events_cdylib.cpp
// (nlohmann marshaling into the host's emit callback); the unit tests don't
// link that. These forwarders route each event's single string payload to
// logos_test's active capture (logos_test::EventCapture / ScopedEventSink —
// see <logos_test.h>), so capability_module_impl.cpp's emit calls resolve.

#include <logos_test.h>

#include "capability_module_impl.h"

using logos_test::recordEvent;

void CapabilityModuleImpl::consentRequired(const std::string& payload) { recordEvent("consentRequired", payload); }
void CapabilityModuleImpl::consentDecided(const std::string& payload)  { recordEvent("consentDecided", payload); }
