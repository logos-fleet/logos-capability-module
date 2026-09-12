# Logos Capability Module

Coordinates permissions and capabilities between Logos modules.

Built with [`logos-module-builder`](https://github.com/logos-co/logos-module-builder). The implementation is a plain **Qt-free** C++ class deriving `LogosModuleContext` — no `Q_OBJECT` / `Q_INVOKABLE` boilerplate, and no dispatch marker either: its public methods *are* its API. `metadata.json` declares `interface: "universal"`, so the builder derives the contract from the impl header named by `codegen.impl_header` and generates every piece of framework plumbing — the LIDL contract, the Qt plugin glue, the C-ABI exports, packaging.

This README used to describe two earlier shapes, so for orientation: the module was
`interface: "provider"` (a `LogosProviderBase` subclass whose API methods carried a
`LOGOS_METHOD` marker — neither the base class nor the marker exists any more) up to 22e54ff,
then a handcrafted `interface: "legacy"` Qt plugin with `Q_OBJECT` / `Q_INVOKABLE` methods,
and finally `universal` as of fc39b1b. See `docs/docs.md` for the current three-step pipeline.

## Build

```bash
nix build              # produces result/lib/capability_module_plugin.{dylib,so}
nix build .#lgx        # builds the .lgx package
nix build .#unit-tests # builds the test binary
```

To enter a development shell:

```bash
nix develop
```

## Test

```bash
nix flake check                                                 # runs all checks
nix build .#checks.<system>.unit-tests -L                       # builds + runs tests
./result/bin/capability_module_tests                            # run the binary directly
./result/bin/capability_module_tests --filter requestModule     # filter by name
```

## Layout

```
src/
├── capability_module_impl.{h,cpp}   # CapabilityModuleImpl : LogosModuleContext — plain,
│                                    # Qt-free public methods; no dispatch macros
└── capability_module.lidl           # dead leftover from when this was a handcrafted Qt
                                     # plugin; nothing reads it any more (see below)
tests/
├── CMakeLists.txt
├── main.cpp
├── test_capability_module.cpp
├── test_consent.cpp                 # the 4.7.3 per-module consent gate
└── capability_module_events_test.cpp # Qt-free bodies for the two consent events
docs/docs.md                         # module specification
doctests/                            # end-to-end composition doc-test
metadata.json                        # interface: universal; codegen.{impl_class,impl_header};
                                     # host_services; nix.* build config
flake.nix                            # logos-module-builder (master), calls mkLogosModule
CMakeLists.txt                       # calls logos_module()
```

There is no hand-written plugin loader. `src/capability_module_loader.h` was real under the
original module-builder layout but was deleted in 22e54ff, long before the `universal`
migration; the plugin entry point is generated into `generated_code/`, which is not checked
in.

`src/capability_module.lidl` was the hand-committed contract this module needed while it was
an `interface: "legacy"` Qt plugin, so that cross-compiled builds (which cannot `dlopen` the
PE they just produced) still had a typed API to hand downstream. A `universal` module
publishes a `lidl` flake output derived from its impl header, and the builder prefers that
over the committed file, so this one is now unreferenced.

## Dependencies

- [logos-module-builder](https://github.com/logos-co/logos-module-builder) — pulls in `logos-cpp-sdk`, `logos-module`, `logos-test-framework`, and Qt6 (Core + RemoteObjects).
