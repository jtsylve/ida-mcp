# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Security-focused prompts — crypto identification."""

from __future__ import annotations

from fastmcp import FastMCP


def register(mcp: FastMCP):
    @mcp.prompt(
        description=(
            "Scan for known cryptographic constants to identify crypto algorithms in use."
        ),
    )
    def find_crypto_constants() -> str:
        return """\
Search for known cryptographic constants in the binary. For each algorithm, \
search for its characteristic constants:

**AES**:
- S-box: search_bytes for "637c777bf26b6fc53001672bfed7ab76"
- Inverse S-box: search_bytes for "52096ad53036a538bf40a39e81f3d7fb"
- Rcon: find_immediate for 0x01000000, 0x02000000, 0x04000000

**SHA-256**:
- Round constants: find_immediate for 0x428a2f98, 0x71374491, 0xb5c0fbcf
- Initial hash: find_immediate for 0x6a09e667, 0xbb67ae85

**SHA-1**:
- find_immediate for 0x67452301, 0xEFCDAB89, 0x98BADCFE

**MD5**:
- find_immediate for 0xd76aa478, 0xe8c7b756, 0x242070db
- T-table: search_bytes for "78a46ad7"

**CRC-32**:
- Polynomial: find_immediate for 0xEDB88320, 0x04C11DB7
- Table prefix: search_bytes for "0000000096300777"

**ChaCha20/Salsa20**:
- "expand 32-byte k": search_bytes for "657870616e642033322d62797465206b"
- "expand 16-byte k": search_bytes for "657870616e642031362d62797465206b"

**RSA / big-number markers**:
- find_immediate for 0x10001 (common public exponent)

**Blowfish**:
- P-array: find_immediate for 0x243F6A88, 0x85A308D3

For each hit:
1. Report the address, algorithm, and which constant matched
2. Use get_xrefs_to to find the function(s) that reference it
3. Briefly describe the function (decompile if small) to confirm crypto usage

Present results grouped by algorithm."""
