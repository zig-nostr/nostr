/* Umbrella header for the libsecp256k1 C API surface this library binds.
 *
 * Kept as the single `translate-c` root (see build.zig) so that the modules
 * needing Schnorr signatures / x-only keys (src/keys.zig) and the module
 * needing ECDH (src/nip44.zig) share one generated Zig binding with
 * consistent types. The corresponding upstream modules are enabled at
 * compile time via -DENABLE_MODULE_SCHNORRSIG / -DENABLE_MODULE_EXTRAKEYS /
 * -DENABLE_MODULE_ECDH.
 */
#include <secp256k1_schnorrsig.h>
#include <secp256k1_ecdh.h>
