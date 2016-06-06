## SMS4 Sub-Library of GMSSL

Encryption modes:

 * ECB: encrypt or decrypt a block, process only one block per call.
 * CBC: process variable length input with zero padding, IV works as both input and output.
 * CFB: same as CBC
 * OFB: same as CBC

Optimization for specific architecture:

 * AVX2: support ECB, CTR and CBC-decrypt (todo)
 * KNC-NI: support ECB, CTR and CBC-decrypt (todo)

Some future plans:

 * more operation modes, GCM, XTS, FFX, OFB ...
 * more optimiazations: ARM/NEON, X86 ASM, GPU, ...
 * secure implementation: Bit Slicing, Timing attack ...
 * formally verified.


