#!/usr/bin/env python3
"""
Generate per-GPU akira-bruteforce config JSON files for a distributed T3/T4 search.

The search space is the cartesian product of:
  T3 candidates : [t3_start, t3_end)           nanoseconds
  T4-T3 gap     : [offset, offset+range)        nanoseconds

The T3 window is split across GPUs proportionally to their relative speed so
all GPUs finish at roughly the same time.

Each output config covers one GPU's T3 slice:
  start_timestamp         = first T3 candidate for this GPU
  count                   = t3_slice + offset + brute_force_time_range
  offset                  = minimum T4-T3 gap (ns)
  brute_force_time_range  = gap search width (ns)

Usage example (31 GPUs, 30x RTX 8000 + 1x RTX 5050):
  python gen_configs.py \\
    --t3-start 1786077189450000000 --t3-end 1786077189870000000 \\
    --offset 1000000 --range 800000 \\
    --plaintext 0x4e4b5f4152494b41 --encrypted 0x626f1e63b2d7e96f \\
    --gpus 31 --gpu-speed 1.0,1.0,...,0.69 \\
    --out-dir search_configs --prefix config_gpu
"""

import json
import argparse
import os
import sys


def generate_configs(
    t3_start,
    t3_end,
    offset,
    time_range,
    matches,
    gpu_speeds,
    out_dir=".",
    prefix="config_gpu",
):
    t3_window = t3_end - t3_start
    if t3_window <= 0:
        raise ValueError(f"t3_end must be > t3_start (got window={t3_window})")

    total_speed = sum(gpu_speeds)
    n = len(gpu_speeds)
    current_start = t3_start
    configs = []

    for i, speed in enumerate(gpu_speeds):
        if i == n - 1:
            t3_slice = t3_end - current_start
        else:
            t3_slice = int(t3_window * speed / total_speed)
            t3_slice = max(t3_slice, 1)

        count = t3_slice + offset + time_range

        cfg = {
            "count": count,
            "start_timestamp": current_start,
            "brute_force_time_range": time_range,
            "offset": offset,
            "matches": matches,
        }

        os.makedirs(out_dir, exist_ok=True)
        out_path = os.path.join(out_dir, f"{prefix}{i}.json")
        with open(out_path, "w") as f:
            json.dump(cfg, f, indent=2)

        configs.append({
            "gpu": i,
            "start_timestamp": current_start,
            "t3_slice_ns": t3_slice,
            "count": count,
            "out_path": out_path,
        })
        current_start += t3_slice

    return configs


def parse_match_args(args):
    if not args.plaintext or not args.encrypted:
        return None
    entry = {
        "filename": args.filename or "target",
        "plaintext": args.plaintext,
        "encrypted": args.encrypted,
        "bitmask": args.bitmask,
    }
    return [entry]


def main():
    p = argparse.ArgumentParser(
        description="Generate per-GPU akira-bruteforce config files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--t3-start", type=int, required=True,
                   help="First T3 candidate (nanoseconds, absolute timestamp)")
    p.add_argument("--t3-end",   type=int, required=True,
                   help="Last T3 candidate, exclusive (nanoseconds)")
    p.add_argument("--offset",   type=int, required=True,
                   help="Minimum T4-T3 gap in ns  [config: offset]")
    p.add_argument("--range",    type=int, required=True, dest="time_range",
                   help="Gap search width in ns    [config: brute_force_time_range]")
    p.add_argument("--plaintext",  type=str, required=True,
                   help="Known plaintext bytes as 0x-prefixed hex (8 bytes = 16 hex digits)")
    p.add_argument("--encrypted",  type=str, required=True,
                   help="Corresponding ciphertext bytes as 0x-prefixed hex")
    p.add_argument("--bitmask",    type=str, default="0xffffffffffffffff",
                   help="Comparison bitmask (default: 0xffffffffffffffff = all bits)")
    p.add_argument("--filename",   type=str, default="target",
                   help="Label for the match entry (used in output messages)")
    p.add_argument("--gpus",      type=int, required=True,
                   help="Total number of GPUs")
    p.add_argument("--gpu-speed", type=str, default=None,
                   help="Comma-separated relative GPU speeds, one per GPU "
                        "(e.g. '1.0,1.0,0.69'); default: equal weight")
    p.add_argument("--out-dir",  type=str, default=".",
                   help="Directory for output config files (created if absent)")
    p.add_argument("--prefix",   type=str, default="config_gpu",
                   help="Filename prefix  (default: config_gpu → config_gpu0.json …)")

    args = p.parse_args()

    if args.gpu_speed:
        speeds = [float(x) for x in args.gpu_speed.split(",")]
        if len(speeds) != args.gpus:
            p.error(f"--gpu-speed must supply exactly {args.gpus} values, got {len(speeds)}")
    else:
        speeds = [1.0] * args.gpus

    matches = parse_match_args(args)
    if not matches:
        p.error("--plaintext and --encrypted are required")

    configs = generate_configs(
        t3_start=args.t3_start,
        t3_end=args.t3_end,
        offset=args.offset,
        time_range=args.time_range,
        matches=matches,
        gpu_speeds=speeds,
        out_dir=args.out_dir,
        prefix=args.prefix,
    )

    t3_window = args.t3_end - args.t3_start
    print(f"T3 window : {args.t3_start} → {args.t3_end}  ({t3_window:,} ns = {t3_window/1e6:.3f} ms)")
    print(f"Gap range : offset={args.offset:,} ns  range={args.time_range:,} ns")
    print(f"GPUs      : {len(configs)}")
    print()
    for c in configs:
        print(f"  [{c['gpu']:2d}] start={c['start_timestamp']}  "
              f"slice={c['t3_slice_ns']:>12,} ns  "
              f"count={c['count']:>12,}  →  {c['out_path']}")


if __name__ == "__main__":
    main()
