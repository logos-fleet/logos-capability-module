// The token generator this module owns since boost left (src/uuid.h).
//
// The minted UUID IS the auth token, so what these pin is not "it looks like a
// UUID" but the three things a token broker would be broken without: the bits
// the RFC reserves are actually set, two draws are never the same, and the
// random source fills every byte it was asked for.
//
// The uniqueness case is not a probability argument dressed up as a test. A
// generator that returns a CONSTANT -- which is what a swallowed CSPRNG
// failure, or a std::random_device that is permitted to be deterministic,
// produces -- fails it on the second draw, every time. That is the failure this
// file exists for.

#include <logos_test.h>

#include "uuid.h"

#include <cstdint>
#include <set>
#include <string>

using logos_capability::randomBytes;
using logos_capability::uuidV4;

namespace {

bool isLowerHex(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
}

}  // namespace

LOGOS_TEST(uuid_has_the_canonical_shape) {
    const std::string u = uuidV4();
    LOGOS_ASSERT_EQ(u.size(), std::size_t(36));
    for (std::size_t i = 0; i < u.size(); ++i) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            LOGOS_ASSERT(u[i] == '-');
        } else {
            LOGOS_ASSERT(isLowerHex(u[i]));
        }
    }
}

LOGOS_TEST(uuid_carries_the_version_and_variant_the_rfc_reserves) {
    // RFC 4122 4.4: the version nibble is the 13th hex digit (index 14 with the
    // hyphens) and the variant is the 17th (index 19), one of 8/9/a/b.
    for (int i = 0; i < 64; ++i) {
        const std::string u = uuidV4();
        LOGOS_ASSERT(u[14] == '4');
        LOGOS_ASSERT(u[19] == '8' || u[19] == '9' || u[19] == 'a' || u[19] == 'b');
    }
}

LOGOS_TEST(uuid_two_draws_are_never_the_same) {
    std::set<std::string> seen;
    for (int i = 0; i < 4096; ++i) {
        LOGOS_ASSERT(seen.insert(uuidV4()).second);
    }
    LOGOS_ASSERT_EQ(seen.size(), std::size_t(4096));
}

LOGOS_TEST(uuid_random_source_fills_every_byte_it_was_asked_for) {
    // A short read that reported success would leave the tail of the buffer at
    // its initial value, which is the one way a UUID can be well-formed and
    // still carry less entropy than it claims. 0xAB is a legitimate random
    // byte, so a handful surviving is expected (~1 in 256 per byte, i.e. one on
    // average over this buffer); a tail left whole is not.
    std::uint8_t buf[256];
    for (auto& b : buf) b = 0xAB;
    randomBytes(buf, sizeof(buf));

    int untouched = 0;
    for (auto b : buf) {
        if (b == 0xAB) ++untouched;
    }
    LOGOS_ASSERT(untouched < 16);
}
