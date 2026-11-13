---
name: akira-decryptor
description: Recover authorized files encrypted by the Akira ESXi/Linux V3 variant by searching timestamp-derived KCipher2 and ChaCha8 material on NVIDIA GPUs. Use for the supported sample and known-plaintext recovery; do not use for Windows Akira, unknown variants, or ransomware execution.
---

# Akira Decryptor

Recover a key and decrypt a file only when the user owns or is authorized to recover it.

## Confirm the supported case

Before building or launching a search, confirm all of these:

- The encryptor SHA-256 is `bcae978c17bcddc0bf6419ae978e3471197801c36f73cff2fc88cecbe3d88d1a` (Akira Linux/ESXi V3).
- An encrypted `*.akira` file and its original `stat`/mtime are available.
- At least eight known plaintext bytes and their file offset are known.
- The corresponding ciphertext can be read from the encrypted file.
- The user has approved the GPU hosts, GPU indices, and expected search cost.

If the sample identity is unknown, help verify it first. Do not claim compatibility from the `.akira` suffix alone. This method searches wall-clock timestamps used by Yarrow-256; it does not break RSA.

Never execute the ransomware as part of this skill. Never decrypt the only copy: make a working copy and preserve its timestamps and hash.

## Prepare the maintained fork

Use the current repository when already inside it. Otherwise clone `https://github.com/juaninf/akira-bruteforce`.

On Debian or Ubuntu, install `nettle-dev`, `libssl-dev`, `nvidia-cuda-toolkit`, `nvidia-cuda-toolkit-gcc`, `build-essential`, `git`, and `nasm`. Check the GPU compute capability before building; the Makefile's CUDA architecture must match the host. Then run `make` and `make -C util`. Confirm these tools exist and are binaries for the current host:

- `akira-bruteforce`
- `decrypt`
- `util/readhex`

If an existing `decrypt` binary is for another operating system or architecture, rebuild it with `make -B decrypt` after installing the development headers.

The maintained fork contains the corrected `run2` bounds check. Do not silently fall back to an older upstream binary.

## Collect the search values

1. Read the ciphertext at the known-plaintext offset with `./util/readhex <file.akira> [offset]`.
2. Convert the file mtime to epoch nanoseconds. ESXi/VMFS commonly stores whole-second mtime, so search the complete second unless a trusted log narrows it.
3. Choose the T4−T3 gap band. Prefer a measurement from the same ESXi build. Without one, state the uncertainty and start with a conservative band no wider than 3 ms.
4. Record the GPU count and relative speeds. Do not use GPUs owned by another user or workload.

## Generate and run the search

Resolve the absolute directory containing this `SKILL.md` as `SKILL_DIR`; do not assume the current working directory contains the skill. Use `$SKILL_DIR/scripts/gen_configs.py` to split the T3 window across GPUs. Its main arguments are `--t3-start`, `--t3-end`, `--offset`, `--range`, `--plaintext`, `--encrypted`, `--gpus`, and `--out-dir`. Pass `--prefix gpu` because the launch and monitor scripts expect files named `gpu<N>.json`.

Before launch, make an explicit assignment table with `logical slice`, `host`, and `physical GPU`. Every generated slice from 0 through N−1 must appear exactly once; no physical GPU may appear twice on one host. Copy the assigned configs to each approved host and verify that their T3 ranges are complete and non-overlapping.

From the directory containing the built binary, launch with `$SKILL_DIR/scripts/launch_gpus.sh <config-dir> <physical-gpu:logical-slice>...`. For example, `2:0 3:1` runs `gpu0.json` on physical GPU 2 and `gpu1.json` on physical GPU 3. Monitor with the same mappings using `$SKILL_DIR/scripts/monitor_gpus.sh`.

Treat a match as a candidate until it reproduces the known plaintext. Preserve the config, log, binary commit, GPU assignment, and reported T3/T4 values.

If the approved window finishes without a match, stop. Do not widen the T3 window, gap band, change known plaintext, or relaunch without showing the completed coverage and receiving new user approval.

## Recover ChaCha8 timestamps when needed

After T3 is verified, choose known plaintext from a ChaCha8-encrypted region and read its ciphertext at the same offset. Create a JSON config containing:

```json
{
  "t3_ts": 1741841294374553498,
  "t3_t1_offset": 3000000,
  "t1_t2_start_offset": 1300000,
  "t1_t2_end_offset": 2000000,
  "encrypted": "0x03d3319ddbf9caee",
  "plaintext": "0x0"
}
```

`t3_t1_offset` is the maximum distance searched backward from T3 for T1. The T1/T2 fields define the tested T2−T1 gap. Run `./akira-bruteforce runchacha <config.json> [physical-gpu]`. When it reports `index` and `offset`, use `T1 = index` and `T2 = index + offset`. Treat the result as unverified until decryption reproduces the known ChaCha8 plaintext. The same stopping rule applies: do not expand either range without new approval.

## Decrypt and verify

Work on a copy because `decrypt` changes the file in place and removes the `.akira` suffix.

Use either:

```text
./decrypt <copy.akira> <T1> <T2> <T3> <T4>
./decrypt bykey <copy.akira> <chacha8-key> <chacha8-nonce> <kcipher2-key> <kcipher2-iv>
```

Passing `0 0` for T1/T2 verifies only the KCipher2 region. If the file also contains ChaCha8 regions, run the smaller T1/T2 search anchored to the recovered T3 before claiming full recovery.

Verify the known plaintext, expected file structure, and output size. Report partial recovery as partial; never call a KCipher2 spot check a complete decryption.

For a small regression case and exact expected timestamps, read [references/known-target.md](references/known-target.md).
