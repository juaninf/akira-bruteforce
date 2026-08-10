# Akira ESXi — Recovering the Key of a Known Target by Timestamp Brute-Force

**Target:** `known_random.bin.akira` (Akira ESXi/Linux encryptor)
**Result:** KCipher2 key/IV timestamps recovered — file is decryptable.
**Date:** 2026-08-07 → 2026-08-10

---

## 1. Result (TL;DR)

The nanosecond timestamps that seed the KCipher2 stream cipher for `known_random.bin.akira` were recovered by GPU brute-force:

| Value | |
|---|---|
| **T3** (KCipher2 key seed) | `1786077189676504072` |
| **T4** (KCipher2 IV seed)  | `1786077189678050965` |
| gap `T4 − T3`              | `1,546,893` ns (**1.547 ms**) |

Confirmed by a full 64-bit known-plaintext match (false-positive probability ≈ 2⁻⁶⁴). Found on cluster pod `server2`, GPU 2, after ~4 h on 31 GPUs.

From T3/T4 the KCipher2 key = `Yarrow(T3)` and IV = `Yarrow(T4)`, which decrypt the KCipher2-encrypted regions of the file.

---

## 2. Background: how Akira (ESXi) derives keys

The sample (`SHA256 bcae978c17bcddc0bf6419ae978e3471197801c36f73cff2fc88cecbe3d88d1a`, from virus.exchange) generates all key material from **nanosecond wall-clock timestamps** run through **nettle's Yarrow-256** PRNG, seeded with the decimal string of the timestamp:

```
gen_key(t):  yarrow256_init; yarrow256_seed(seed = "%lld" % t); yarrow256_random(32)
```

Each file consumes **four** timestamps, sampled microseconds–milliseconds apart:

| Timestamp | Seeds | Bytes |
|---|---|---|
| **T1** | ChaCha8 key   | 32 |
| **T2** | ChaCha8 nonce | 16 |
| **T3** | KCipher2 key  | 16 |
| **T4** | KCipher2 IV   | 16 |

The key material is stored in a **512-byte RSA-OAEP trailer** appended to each file, encrypted with the attacker's public key (undecryptable without their private key — hence the need to brute-force the timestamps instead).

Cipher layout (this sample): **offset 0 of the file is KCipher2**; ChaCha8 covers other regions. The GPU tool `akira-bruteforce` reproduces `Yarrow(t)` on-GPU (`multihash`); empirically `multihash(t) == Yarrow(t)` with each 32-bit word byte-swapped (the `swap32` that `decrypt.c` applies before `kcipher2_init`).

The brute-force is a **2-D search** over `(T3, gap = T4−T3)`: for each candidate T3 it derives the key, and for each candidate gap it derives the IV from `hash[T3 + gap]`, then checks whether the KCipher2 keystream matches a known-plaintext byte-block.

---

## 3. The target

- Host: `esxi` (esxi-auto.local, ESXi 7.0U3), datastore `6a47f619-d79de22d-449a-000c29ec6917`.
- File: `akira_known_target/known_random.bin.akira`, 66,128 bytes = 65,616 plaintext + 512 trailer.
- Plaintext (we control it; a backup was kept in `akira_known_plain_backup/`):
  ```
  AKIRA_KNOWN_PREFIX_2026_07_09_1332UTC\n
  HELLO_WORLD_KNOWN_TEXT_FOR_DECRYPTOR_TEST\n
  + 65536 bytes /dev/urandom
  ```
- mtime `2026-08-07 04:33:09` (epoch 1786077189); plaintext-backup mtime `04:33:07`.

**Known-plaintext block (offset 0, KCipher2):**

| | value (little-endian `readhex`) |
|---|---|
| plaintext (`AKIRA_KN`) | `0x4e4b5f4152494b41` |
| ciphertext             | `0x626f1e63b2d7e96f` |
| bitmask                | `0xffffffffffffffff` |

(Verified: KCipher2 keystream from the recovered key/IV equals `plaintext ⊕ ciphertext` = `7c 0d a9 58 41 b0 2a d5`.)

---

## 4. Methodology

### 4.1 Extract the known-plaintext
Read the first 8 bytes of the plaintext backup and of the `.akira` at the same offset (offset 0). Confirmed offset 0 is encrypted (bytes differ) and offset 65535 is *not* (bytes identical → no clean ChaCha known-plaintext there on this small file).

### 4.2 Get ground-truth timing (the key move)
Guessing the gap from a reference machine (the tinyhack 1.11 ms) was wrong. Instead we **measured** it on this host:

1. `public-key-patch/patch-public-key sample pub2.der sample-patched` — re-point the trailer to *our* RSA key so we can read it back.
2. `timing-patch-2/patcher sample-patched akira-ts` — inject hooks that log every key-gen timestamp to `/tmp/log.bin`.
3. Detonate `akira-ts --encryption_path=<throwaway dir>` on the isolated ESXi lab.
4. `read-log` / `public-key-patch/read-trailer <file>.akira log.bin` → prints **T1,T2,T3,T4 and the gaps**.

Build deps (installed with `sudo apt-get`): `nasm`, `nettle-dev`. The committed `read-trailer` binary is macOS — rebuild on Linux (`gcc read-trailer.c -o read-trailer -lcrypto -lhogweed -lnettle`).

### 4.3 Measured gap distribution (T4 − T3) on this host
- **Single isolated file:** **1.234 ms**.
- 7-file batch (CPU contention): 1.38 – 2.61 ms (mean ~1.84 ms).
- (T3−T1 ≈ 2.9–4.2 ms, T2−T1 ≈ 1.5–2.5 ms.)

So the reference 1.11 ms was *below* reality — every earlier search band missed for this reason.

### 4.4 Constrain the T3 window
ESXi/VMFS **mtime is whole-second resolution**, so mtime `:09` only says T3 ∈ `[…189.0e9, …190.0e9)`. `hostd.log` timestamps the orchestration SSH sessions to the **millisecond**:

```
04:33:07.810 → 08.282   (created plaintext; backup mtime :07)
04:33:09.465 → 09.862   (ran encryptor; .akira mtime :09)
```

→ encryption happened inside `09.465 – 09.862`, collapsing T3 from ~1 s to **~420 ms**: `[…189.45e9, …189.87e9]`.

### 4.5 Fix the `run2` kernel bug
`encrypt_and_search_offset` (the fast method's kernel) had:
```c
size_t idx_offs = idx + offset;
if (idx_offs >= N) return;      // BUG: N == limit, should be num
```
`idx_offs` indexes the full `num`-sized hash array, not `limit`. Effect: T3 indices in `[limit−offset, limit)` are silently skipped; **when `offset ≥ limit` (small `count`), every thread returns → nothing is searched.** Fix = drop the guard (host guarantees `idx_offs < num` for `idx < limit`). Diagnosed by: `run` (slow method, different kernel) found a known answer that `run2` missed on the identical config; reading the kernel showed the `offset ≥ limit` condition. Rebuilt on all pods (`sm_75`) and the laptop (`sm_120`).

### 4.6 GPU search
Search space: **T3 `…189.45 – 189.87e9` (420 ms) × gap `1.0 – 1.8 ms`** (wide band around single-file 1.234 ms, with margin) ≈ 3.4×10¹⁴ combos.

31 GPUs, sharded by contiguous T3 slice, weighted by speed so all finish together:
- 30× Quadro RTX 8000 across pods `tii_cuda_server` (GPUs 2–7; 0–1 were another tenant), `server1`, `server2`, `server4` (~8.66×10⁸ combos/s each).
- 1× RTX 5050 Laptop (WSL2, `-arch=sm_120`, ~6×10⁸ combos/s, smaller slice).

Per-GPU config (`run2` = fast method):
```json
{ "count": 15480000, "start_timestamp": "<slice base>",
  "brute_force_time_range": 800000, "offset": 1000000,
  "matches": [{"plaintext":"0x4e4b5f4152494b41","encrypted":"0x626f1e63b2d7e96f","bitmask":"0xffffffffffffffff"}] }
```
(`count = T3_slice + offset + range`; the slower laptop got `count = 11280000` / a 9.48 ms T3 slice.)

Wall-clock ~4 h. Hit at T3 = `1786077189676504072`, gap `1,546,893` ns — inside `server2/gpu2`'s slice, self-consistent.

---

## 5. Why it works (and why earlier attempts didn't)

| Failure earlier | Root cause | Fix |
|---|---|---|
| Cluster sweeps found nothing | **Wrong bands**: gap guessed at ~1.11 ms (real ~1.5 ms); T3 window `[187,189]e9` (real `[189,190)e9`, mtime is second-res) | Measure gap via timing patch; derive T3 window from `hostd.log` ms timestamps |
| Small validation configs found nothing even at correct values | **`run2` kernel bug**: `idx_offs >= N` guard zeroes the search when `offset ≥ limit` | One-line fix (`N` → `num`, i.e. remove guard) |

The crypto and timestamp math were correct throughout; the two failures were band-selection and a kernel bounds bug, and they masked each other (same empty-output symptom, opposite causes).

---

## 6. Reproduction (recovered values)

```
T3 = 1786077189676504072      # KCipher2 key  = Yarrow(T3)
T4 = 1786077189678050965      # KCipher2 IV   = Yarrow(T4)
gap = 1546893 ns (1.547 ms)
```

Confirm a single GPU re-derives it quickly (fixed binary):
```
# config with start_timestamp = T3 - small, offset = gap - small, count > offset+range
./akira-bruteforce run  <cfg.json> <gpu>     # slow, always correct
./akira-bruteforce run2 <cfg.json> <gpu>     # fast, correct after the fix
```

---

## 7. Remaining work

1. **Decrypt & verify:** derive KCipher2 key/IV from T3/T4, run `decrypt` on `known_random.bin.akira`, diff against the plaintext backup.
2. **ChaCha regions (if any):** if parts don't decrypt, the file is layered and needs **T1/T2**. That is now a *cheap* second brute-force — anchored to the known T3, T1 sits only a few ms earlier (use the `runchacha` config with `t3_ts = T3`).
3. Upstream the one-line `run2` fix.
