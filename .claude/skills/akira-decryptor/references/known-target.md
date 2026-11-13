# Known-target regression

Use this only to check the toolchain. The fixture is `tests/known_random.bin.akira`.

## Inputs

- Plaintext size before the RSA trailer: 65,616 bytes.
- Encrypted fixture size: 66,128 bytes.
- Mtime second: `1786077189`.
- Narrowed T3 window: `1786077189450000000` through `1786077189870000000`.
- Plaintext at offset 0: ASCII `AKIRA_KN`, encoded as `0x4e4b5f4152494b41`.
- Ciphertext at offset 0: `0x626f1e63b2d7e96f`.
- Bitmask: `0xffffffffffffffff`.
- Gap band: offset `1000000`, range `800000` nanoseconds.

Generate configs with:

```text
python .claude/skills/akira-decryptor/scripts/gen_configs.py \
  --t3-start 1786077189450000000 --t3-end 1786077189870000000 \
  --offset 1000000 --range 800000 \
  --plaintext 0x4e4b5f4152494b41 --encrypted 0x626f1e63b2d7e96f \
  --gpus 1 --out-dir search_configs --prefix gpu
```

For a fast check, narrow T3 to `1786077189676000000` through `1786077189677000000`, and use offset `1500000`, range `100000`.

The expected match is:

```text
T3 = 1786077189676504072
T4 = 1786077189678050965
gap = 1546893 ns
```

Copy the fixture before testing, then run:

```text
./decrypt <fixture-copy.akira> 0 0 1786077189676504072 1786077189678050965
```

The KCipher2 region must begin with:

```text
AKIRA_KNOWN_PREFIX_2026_07_09_1332UTC
HELLO_WORLD_KNOWN_TEXT_FOR_DECRYPTOR_TEST
```

This is a KCipher2-only check. T1/T2 are still needed for any ChaCha8 regions.
