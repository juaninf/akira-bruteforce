# Task: Create a Claude Code skill named "akira-decryptor"

Create a skill that helps someone recover the key for a file encrypted by the
Akira ESXi/Linux ransomware and decrypt it, using a GPU brute-force of the
nanosecond timestamps that seed the cipher.

## Scope and identification (show this FIRST, before doing anything)

Open the skill by telling the user exactly what it is and its limits:
- This decryptor targets the **Akira ESXi/Linux variant** with SHA256
  `bcae978c17bcddc0bf6419ae978e3471197801c36f73cff2fc88cecbe3d88d1a`.
- It works by brute-forcing the wall-clock timestamps (T3/T4 → KCipher2 key/IV;
  T1/T2 → ChaCha8 key/nonce) that were fed into the Yarrow-256 PRNG to derive
  the per-file key. It requires a **known-plaintext** block from the file and
  **GPU(s)** to run the search. It does NOT break RSA.
- Ask the user to confirm their sample matches that hash, and that they have a
  known-plaintext snippet, before continuing. If unsure, help them verify the
  hash (`sha256sum`) first.

## Inputs to collect (ask the user)

1. Path to the encrypted file (`*.akira`).
2. The `stat` output of the encrypted file (mtime is used to derive the T3
   search window — ESXi/VMFS mtime is whole-second resolution).
3. The IP/hostname(s) of the GPU server(s), plus how many GPUs each has and
   their relative speed if known (for load balancing).
4. The known plaintext and its offset, and the corresponding ciphertext.
   Explain how to obtain them: plaintext depends on file type (see the repo
   README/blog); ciphertext via `./util/readhex <file.akira> [offset]`.
5. (Optional) If the originating ESXi host is reachable, whether they can
   measure the real T4−T3 gap with `timing-patch-2` — otherwise default to a
   wide gap band.

## Setup

- Clone and build the fork (which contains the run2 bug fix and the helper
  scripts): `https://github.com/juaninf/akira-bruteforce/`
- Follow that repo's README. Build deps (Debian/Ubuntu):
  `apt-get install -y nettle-dev libssl-dev nvidia-cuda-toolkit
   nvidia-cuda-toolkit-gcc build-essential git nasm`, then `make`.
- Match the CUDA arch to the hardware (cluster Quadro RTX 8000 = sm_75; newer
  cards differ).

## Generate configs

Use `gen_configs.py` (documented in the README). Derive the parameters:
- **T3 window** (`--t3-start`/`--t3-end`): from the file mtime. Because mtime is
  second-resolution, the window is the whole second `[mtime, mtime+1s)`; narrow
  it further if the user has millisecond-precision logs (e.g. `hostd.log`).
- **Gap band** (`--offset` = minimum T4−T3 gap, `--range` = width): default to a
  wide band and cap the total gap search at **3 ms** unless the user measured a
  tighter value.
- **Known-plaintext** (`--plaintext`/`--encrypted`) from the inputs above.
- **GPU count/speed** (`--gpus`/`--gpu-speed`): one slice per GPU, weighted so
  all finish together.

Example invocation:

    python gen_configs.py \
      --t3-start 1786077189450000000 --t3-end 1786077189870000000 \
      --offset 1000000 --range 800000 \
      --plaintext 0x4e4b5f4152494b41 --encrypted 0x626f1e63b2d7e96f \
      --gpus 31 --gpu-speed 1.0,1.0,...,0.69 \
      --out-dir search_configs

## Distribute and run

- Copy the encrypted file and the per-GPU configs to each GPU server.
- Partition GPUs by index list (e.g. `0 1 2 3 ...`; on hosts where some GPUs
  belong to another tenant, use only the free indices such as `2 3 4 5 6 7`).
- Launch with the repo's `launch_gpus.sh` (runs `akira-bruteforce run2` per GPU
  in the background). Monitor with `monitor_gpus.sh` (progress from checkpoint
  files, matches from logs/`output.txt`).

## Decrypt and verify

- When a match reports T3/T4 (and T1/T2 if a ChaCha8 pass was run), decrypt with
  `./decrypt <file.akira> <T1> <T2> <T3> <T4>`, or `./decrypt bykey <file>
  <chacha8_key> <chacha8_nonce> <kcipher2_key> <kcipher2_iv>` if keys were
  derived directly. Pass `0 0` for T1/T2 to verify just the KCipher2 region.
- Verify the decrypted output against the known plaintext.
- Note: if the file has ChaCha8-encrypted regions, a second (cheap) brute-force
  for T1/T2 anchored to the recovered T3 is needed — use the repo's chacha8
  config.

## Bundle these scripts INTO the skill

The skill must be self-contained. Include (copy from the fork repo, don't assume
they exist on the target machine): `gen_configs.py`, `launch_gpus.sh`,
`monitor_gpus.sh`, and reference the built `akira-bruteforce`, `decrypt`, and
`util/readhex` binaries. Document each in the skill so it can run end-to-end.

## Output format

Write the skill as a `SKILL.md` (name: `akira-decryptor`, with a one-line
description) plus a `scripts/` directory holding the helper scripts above.

---

## Worked example (regression test — the skill should reproduce this)

A fully-solved case. If the skill is built correctly, running it against this
input must recover the T3/T4 below and decrypt the file to the known plaintext.
The encrypted test fixture ships in the repo at `tests/known_random.bin.akira`.

### Input
- File: `tests/known_random.bin.akira` (66,128 bytes = 65,616 plaintext + 512
  RSA trailer), from an ESXi 7.0U3 host.
- `stat` mtime: `2026-08-07 04:33:09` → epoch `1786077189`. Because VMFS mtime is
  whole-second, the raw T3 window is `[1786077189.000e9, 1786077190.000e9)`.
  Host `hostd.log` narrowed the SSH session to `09.465–09.862`, collapsing the
  window to ~420 ms: **t3-start=1786077189450000000, t3-end=1786077189870000000**.
- Known plaintext at **offset 0** (KCipher2 region): first 8 bytes are the ASCII
  `AKIRA_KN`.

      plaintext  = 0x4e4b5f4152494b41
      ciphertext = 0x626f1e63b2d7e96f   (from `./util/readhex known_random.bin.akira`)
      bitmask    = 0xffffffffffffffff

- Measured T4−T3 gap on this host ≈ 1.2–1.8 ms, so search band offset=1,000,000
  range=800,000 (1.0–1.8 ms; within the 3 ms cap).

### Config generation

    python gen_configs.py \
      --t3-start 1786077189450000000 --t3-end 1786077189870000000 \
      --offset 1000000 --range 800000 \
      --plaintext 0x4e4b5f4152494b41 --encrypted 0x626f1e63b2d7e96f \
      --gpus 31 --out-dir search_configs

(31 GPUs solved it in ~4 h; a single GPU anchored near the answer solves it in
seconds — for a fast CI check, use a tight window around the known T3, e.g.
t3-start=1786077189676000000 t3-end=1786077189677000000, offset=1500000,
range=100000, --gpus 1.)

### Expected match

    T3  = 1786077189676504072      # KCipher2 key seed
    T4  = 1786077189678050965      # KCipher2 IV seed
    gap = 1,546,893 ns (1.547 ms)

### Expected decryption

    ./decrypt tests/known_random.bin.akira 0 0 1786077189676504072 1786077189678050965

The KCipher2 region (offset 0) must decrypt so the file now begins with the
literal ASCII:

    AKIRA_KNOWN_PREFIX_2026_07_09_1332UTC
    HELLO_WORLD_KNOWN_TEXT_FOR_DECRYPTOR_TEST

(The remaining bytes are /dev/urandom and stay random; T1/T2=0 leaves any
ChaCha8 regions garbled, which is expected for a KCipher2-only spot check.
`decrypt` works in-place and renames the file, dropping the `.akira` suffix —
work on a copy to keep the fixture intact.)

### Pass/fail criterion

PASS if the search prints T3=1786077189676504072 / T4=1786077189678050965 AND
the decrypted file starts with the `AKIRA_KNOWN_PREFIX_...` / `HELLO_WORLD_...`
lines above. Anything else is a FAIL.
