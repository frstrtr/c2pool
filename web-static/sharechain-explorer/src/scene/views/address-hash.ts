// hash160 of a payout address, for matching a tile against a node that
// publishes a script hash instead of an address (LTC /sharechain/window
// `fee_hash160`). Handles base58check P2PKH/P2SH (25 bytes: version,
// 20-byte hash, checksum) and bech32 witness v0 key hashes (20 bytes).
// Checksums are not verified: a malformed address simply never matches.
// Returns lower-case hex, or null.

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const B32 = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

function hex(bytes: ArrayLike<number>, from: number, to: number): string {
  let s = '';
  for (let i = from; i < to; i++) s += (bytes[i]! & 255).toString(16).padStart(2, '0');
  return s;
}

function base58Bytes(s: string): number[] | null {
  const out: number[] = [];
  for (const ch of s) {
    let carry = B58.indexOf(ch);
    if (carry < 0) return null;
    for (let i = 0; i < out.length; i++) {
      carry += out[i]! * 58;
      out[i] = carry & 255;
      carry >>= 8;
    }
    while (carry > 0) { out.push(carry & 255); carry >>= 8; }
  }
  for (const ch of s) { if (ch !== '1') break; out.push(0); }
  return out.reverse();
}

function bech32Program(s: string): { version: number; program: number[] } | null {
  const lower = s.toLowerCase();
  if (lower !== s && s.toUpperCase() !== s) return null;  // mixed case is invalid
  const sep = lower.lastIndexOf('1');
  if (sep < 1 || lower.length - sep - 1 < 7) return null;
  const data: number[] = [];
  for (const ch of lower.slice(sep + 1)) {
    const v = B32.indexOf(ch);
    if (v < 0) return null;
    data.push(v);
  }
  const words = data.slice(0, -6);  // drop the checksum
  if (words.length < 1) return null;
  const version = words[0]!;
  let acc = 0, bits = 0;
  const program: number[] = [];
  for (const w of words.slice(1)) {
    acc = (acc << 5) | w;
    bits += 5;
    if (bits >= 8) { bits -= 8; program.push((acc >> bits) & 255); }
  }
  return { version, program };
}

export function hash160OfAddress(address: string): string | null {
  if (address.length === 0) return null;
  const seg = /^[a-z]{1,10}1[02-9ac-hj-np-z]{6,}$/i.test(address) ? bech32Program(address) : null;
  if (seg !== null) return seg.version === 0 && seg.program.length === 20 ? hex(seg.program, 0, 20) : null;
  const raw = base58Bytes(address);
  if (raw === null || raw.length !== 25) return null;
  return hex(raw, 1, 21);
}
