#pragma once

// A version-4 UUID from the platform CSPRNG, owned here.
//
// WHY NOT boost. The minted value IS the auth token, so this is the one place
// entropy matters, and boost::uuids::random_generator was the right answer for
// as long as this module was only ever a Qt plugin: boost arrived through the
// Qt plugin backend's propagated inputs without ever being declared.
//
// A BARE module links no Qt, so the header is simply absent -- on macOS, on
// Linux and on every mobile target alike. capability_module has to be a Bare
// module now: a phone's Bundled set is loaded in the Native container, and a
// module-to-module call there mints its token through THIS module
// (LogosAPIClient::mintAndCacheToken), so without it the first cross-module
// call on a phone is refused with "token not recognized". Forty lines of UUID
// is a smaller thing to own than a boost dependency in a token broker.
//
// WHAT IS DELIBERATELY NOT USED: std::random_device. The standard permits it to
// be DETERMINISTIC, and it historically was on MinGW -- which is a live target
// here. Every branch below is a platform CSPRNG and nothing else; there is no
// fallback to a PRNG, because a token from a PRNG that reports success is worse
// than no token at all.
//
// Per platform: arc4random_buf on every Apple OS and on bionic (declared in
// <stdlib.h> everywhere, cannot fail); getentropy on glibc, with /dev/urandom
// under it; RtlGenRandom on Windows, resolved at runtime so this header adds no
// link dependency.

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>

#if defined(_WIN32)
#  include <windows.h>
#elif defined(__APPLE__) || defined(__ANDROID__) || defined(__FreeBSD__) \
   || defined(__OpenBSD__) || defined(__NetBSD__)
// arc4random_buf is the platform CSPRNG on every Apple OS and on bionic, it is
// declared in <stdlib.h> on all of them, and it cannot fail. Deliberately NOT
// getentropy() here: Apple declares that one in <sys/random.h>, which the iOS
// and iOS-simulator SDKs do not ship -- measured, as a fatal "file not found"
// building this module's Bare artifact for aarch64-ios-simulator.
#  define LOGOS_CAPABILITY_ARC4RANDOM 1
#  include <cstdlib>
#else
#  include <cstdio>
#  if defined(__linux__)
#    define LOGOS_CAPABILITY_GETENTROPY 1
#    include <unistd.h>
#  endif
#endif

namespace logos_capability {

// Fills `out` with `len` bytes from the platform's cryptographic RNG. Throws on
// failure -- a caller that swallowed it would mint a predictable token.
inline void randomBytes(std::uint8_t* out, std::size_t len)
{
#if defined(_WIN32)
    // RtlGenRandom, resolved at runtime. The documented name is
    // SystemFunction036 and it has been in advapi32 since Windows XP. Resolved
    // rather than linked so this header adds no link dependency to a module
    // whose CMake is generated.
    using RtlGenRandomFn = BOOLEAN(WINAPI*)(PVOID, ULONG);
    static RtlGenRandomFn rtlGenRandom = []() -> RtlGenRandomFn {
        HMODULE advapi = LoadLibraryA("advapi32.dll");
        return advapi ? reinterpret_cast<RtlGenRandomFn>(
                            GetProcAddress(advapi, "SystemFunction036"))
                      : nullptr;
    }();
    if (!rtlGenRandom || !rtlGenRandom(out, static_cast<ULONG>(len)))
        throw std::runtime_error("capability_module: RtlGenRandom failed");
#elif defined(LOGOS_CAPABILITY_ARC4RANDOM)
    arc4random_buf(out, len);
#else
#  if defined(LOGOS_CAPABILITY_GETENTROPY)
    // getentropy() takes at most this many bytes per call; a UUID needs 16, so
    // the loop is for a caller that asks for more rather than for this one.
    constexpr std::size_t kGetentropyMax = 256;
    std::size_t done = 0;
    while (done < len) {
        const std::size_t remaining = len - done;
        const std::size_t chunk = remaining > kGetentropyMax ? kGetentropyMax : remaining;
        if (getentropy(out + done, chunk) != 0)
            break;
        done += chunk;
    }
    if (done == len)
        return;
#  endif
    // The portable floor, and the only path on a platform with neither of the
    // above.
    std::FILE* f = std::fopen("/dev/urandom", "rb");
    if (!f)
        throw std::runtime_error("capability_module: cannot open /dev/urandom");
    const std::size_t got = std::fread(out, 1, len, f);
    std::fclose(f);
    if (got != len)
        throw std::runtime_error("capability_module: short read from /dev/urandom");
#endif
}

// RFC 4122 section 4.4: 122 random bits, with the version nibble and the two
// variant bits overwritten, formatted 8-4-4-4-12 in lowercase hex. Byte for
// byte the shape boost::uuids::to_string produced, so nothing that reads a
// token can tell the two apart.
inline std::string uuidV4()
{
    std::uint8_t b[16];
    randomBytes(b, sizeof(b));
    b[6] = static_cast<std::uint8_t>((b[6] & 0x0F) | 0x40);   // version 4
    b[8] = static_cast<std::uint8_t>((b[8] & 0x3F) | 0x80);   // variant 1 (10xx)

    constexpr char hex[] = "0123456789abcdef";
    std::string s;
    s.reserve(36);
    for (int i = 0; i < 16; ++i) {
        if (i == 4 || i == 6 || i == 8 || i == 10)
            s.push_back('-');
        s.push_back(hex[b[i] >> 4]);
        s.push_back(hex[b[i] & 0x0F]);
    }
    return s;
}

} // namespace logos_capability
