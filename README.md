Read more about the akira decryption process at https://tinyhack.com


Initial chacha8 code is from : https://github.com/madMAx43v3r/chia-plotter, the license is Apache 2: https://github.com/madMAx43v3r/chia-plotter/blob/master/LICENSE

Initial kcipher2 code is from https://github.com/l00sy4/LCipher2, the license is GPL v3: https://github.com/l00sy4/LCipher2/blob/main/LICENSE

The License for this software is GPL v3

## Requirements

I tested this on Debian Bookworm, but Ubuntu might be easier to setup

```
apt-get install -y nettle-dev libssl-dev nvidia-cuda-toolkit nvidia-cuda-toolkit-gcc build-essential git nasm
```

## Building

```
git clone https://github.com/yohanes/akira-bruteforce
cd akira-bruteforce
make
```

## Testing

I have provided akira encrypted files (the akira ransomware is patched with my own code to record the timing), you can test it by running

```
cd tests
# Note: this will take several minutes and will make your GPU fans spin fast
./akira-bruteforce run2 config-test.json 
```

Meaning of the fields:

* `count`: number nano seconds tested starting from `start_timestamp`
* `start_timestamp`: the timestamp when the test started
* `brute_force_time_range`: the time range in nano seconds that we are testing (the "offset range")
* `offset`: the start offset of the brute force
* `matches`: the list of matches to check, the `filename` is  used to make the output to be more readable

```json
{
	"count": 20000000,
	"start_timestamp": 1741841294358440000,
	"brute_force_time_range": 30000,
	"offset": 1111000,
	"matches": [
		{
            "filename": "zeroes.vmdk",
			"plaintext": "0x0000000000000000",
			"encrypted": "0xd5b71efb8d6969e5",
			"bitmask": "  0xffffffffffffffff"
		},
		{
            "filename" :"ones.vmdk",
			"plaintext": "0x0101010101010101",
			"encrypted": "0x9d1c37f111077987",
			"bitmask": "  0xffffffffffffffff"
		}		
	]	
}
```

Obtaining plaintext: as explained in the blog post, this depends on the file type

Obtaining ciphertext: use a hex editor, or use the "readhex" in the util directory

```
./util/readhex  tests/ones.vmdk.akira
./util/readhex  tests/ones.vmdk.akira 65535 # for chacha8
```

## Distributed GPU search

For large T3 windows (hundreds of milliseconds) split the search across multiple GPUs or machines.

### 1. Generate per-GPU configs

`gen_configs.py` divides a T3 window into per-GPU slices proportional to each GPU's speed:

```
python gen_configs.py \
  --t3-start <first_T3_ns> --t3-end <last_T3_ns> \
  --offset <min_gap_ns> --range <gap_width_ns> \
  --plaintext 0x<8_known_bytes_hex> --encrypted 0x<8_ciphertext_bytes_hex> \
  --gpus <N> [--gpu-speed 1.0,1.0,...,0.69] \
  --out-dir search_configs --prefix config_gpu
```

Key parameters:
* `--t3-start` / `--t3-end`: T3 search window in nanoseconds (derive from file mtime and `hostd.log` for millisecond precision)
* `--offset`: minimum expected T4−T3 gap in nanoseconds (measure on the target ESXi host with `timing-patch-2`)
* `--range`: width of gap band to test (e.g. `800000` = 0.8 ms)
* `--gpu-speed`: relative throughput per GPU — slower GPUs get a proportionally smaller T3 slice

Output: one `config_gpu<N>.json` per GPU, ready to pass to `akira-bruteforce run2`.

### 2. Launch GPUs on a machine

```bash
chmod +x launch_gpus.sh
./launch_gpus.sh search_configs 0 1 2 3 4 5 6 7
```

Each GPU runs in the background (`nohup`) and writes output to `search_configs/gpu<N>.log`.
On `tii_cuda_server` GPUs 0–1 belong to another tenant — use `2 3 4 5 6 7` there.

### 3. Monitor progress

```bash
chmod +x monitor_gpus.sh
# one-shot
./monitor_gpus.sh search_configs 0 1 2 3 4 5 6 7

# continuous (every 10 s)
watch -n 10 ./monitor_gpus.sh search_configs 0 1 2 3 4 5 6 7
```

Progress is read from checkpoint files (`<config>.checkpoint.json`). Matches are reported from
`output.txt` and each GPU's log file. When a match is found the output shows:

```
Found at offset=<gap_ns> ts=<start_timestamp> + <idx>  →  T3=<ts+idx>  T4=<ts+idx+gap>
```

### 4. Decrypt

Once T3 and T4 are recovered:

```bash
# using raw timestamps (T1/T2 required for ChaCha8 regions; pass 0 0 if only KCipher2 matters)
./decrypt <file.akira> <T1> <T2> <T3> <T4>

# using raw hex keys (if you derived key/IV directly from T3/T4 via Yarrow)
./decrypt bykey <file.akira> <chacha8_key_64hex> <chacha8_nonce_32hex> <kcipher2_key_32hex> <kcipher2_iv_32hex>
```

The file is decrypted in-place and renamed (`.akira` suffix removed).

---

## Bug fix — run2 kernel bounds check

This fork fixes a bounds-check bug in `encrypt_and_search_offset` (the kernel used by `run2`).

The original code had:
```c
size_t idx_offs = idx + offset;   // offset = current T4−T3 gap being tested
if (idx_offs >= N) return;        // N = limit — WRONG
```

`idx_offs` indexes the full hash array of size `count`; using `N = limit` (= `count − brute_force_time_range − offset`) silently discards T4 candidates in `[limit, count)`. When `offset ≥ limit` (small `count` configs) every thread returns immediately and nothing is searched. The fix removes the guard — the host already guarantees `idx_offs < count` for all valid threads.

---

## chacha8 bruteforce

An example chacha config is like this

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

* `t3_ts` is the timestamp found by akira-bruteforce
* `t3_t1_offset` is how far back (maximum) the time from `t1` to `t3`
* `t1_t2_start_offset` is the start offset of the brute force
* `t1_t2_end_offset` is the end offset of the brute force
* `encrypted` is the encrypted value
* `plaintext` is the plaintext value
