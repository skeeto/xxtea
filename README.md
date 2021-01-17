# XXTEA file encryption

An **experiment** using [XXTEA][xxtea] as the primitive for all of
encryption, authentication, and key derivation. The ciphertext is
authenticated in strictly-ordered chunks, so it efficiently supports
streaming and large files while avoiding *any* unauthenticated output. The
wire / file format is headerless and indistinguishable from random data.

XXTEA supports variable length blocks, but here it's hardcoded to 128-bit
blocks for all uses. It uses a [Merkle–Damgård construction][md], with
special handling regarding length-extension attacks, for both the custom
KDF and EtA-MAC. The cipher is used in CTR mode, so like with the hash
function, only half of XXTEA is ever needed. See comments in the source
for details about cryptographic design and implementation.

Fully supported on both POSIX and Windows systems, with no dependencies or
byte-order issues.

## Usage

Options follow the usual conventions.

    xxtea <-E|-D> [-h] [-o FILE] [-p PASSWORD] [FILE]

Example, encrypting `message.txt` to `file.enc` (prompts for password):

    $ ./xxtea -E -o file.enc message.txt

Then decrypting output to the terminal:

    $ ./xxtea -D file.enc

## Potential Weaknesses

The XXTEA cipher has weaknesses, but fortunately they do not apply in this
context, a boring, command-line file encryption tool.

All hash inputs are keyed, so the likely second pre-image or known-key
weaknesses on the Merkle-Damgård construction using XXTEA should not
matter. Attackers do not know the hash state when choosing their inputs.

The 128-bit hash state is small, so MAC collisions become a practical risk
after a few terabytes of ciphertext output. That sets the upper safety
limit for encrypting at once. Or, considering XXTEA's speed, do not run
this tool continuously for longer than a day.

## Notes

I wanted to study XXTEA and experiment more with Merkle–Damgård
constructions. I also wanted to dogfood [w64devkit][w64devkit], so except
for the unix bits, this was entirely implemented from scratch within
w64devkit in a fresh Windows installation.

This implementation does not exploit it, but chunks can be authenticated
and decrypted in parallel since the MAC is keyed with both the MAC key and
mode counter. Similarly, all blocks within a chunk can be encrypted and
decrypted in parallel. In other words, the encrypted format supports
random access without sacrificing authentication.


[md]: https://en.wikipedia.org/wiki/Merkle%E2%80%93Damg%C3%A5rd_construction
[w64devkit]: https://github.com/skeeto/w64devkit
[xxtea]: https://en.wikipedia.org/wiki/XXTEA
