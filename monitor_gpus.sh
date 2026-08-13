#!/usr/bin/env bash
# Monitor akira-bruteforce progress across GPUs on this machine.
#
# Usage:
#   ./monitor_gpus.sh <config_dir> <gpu_id> [gpu_id ...]
#
# Example:
#   ./monitor_gpus.sh search_final 2 3 4 5 6 7
#
# Shows per-GPU progress from checkpoint files and any matches found.
# Run repeatedly (or with watch) to track progress:
#   watch -n 10 ./monitor_gpus.sh search_final 2 3 4 5 6 7

set -euo pipefail

if [[ $# -lt 2 ]]; then
    echo "Usage: $0 <config_dir> <gpu_id> [gpu_id ...]"
    exit 1
fi

CONFIG_DIR="$1"; shift
GPUS=("$@")

echo "=== Progress  $(date '+%Y-%m-%d %H:%M:%S') ==="
echo ""

for GPU in "${GPUS[@]}"; do
    CONFIG="${CONFIG_DIR}/gpu${GPU}.json"
    CHECKPOINT="${CONFIG}.checkpoint.json"
    LOG="${CONFIG_DIR}/gpu${GPU}.log"

    printf "GPU %-2s  " "$GPU"

    if [[ ! -f "$CONFIG" ]]; then
        echo "[no config]"
        continue
    fi

    # Read total enc_count (brute_force_time_range) from config
    TOTAL=$(python3 -c "import json; d=json.load(open('${CONFIG}')); print(d['brute_force_time_range'])" 2>/dev/null || echo "?")

    if [[ -f "$CHECKPOINT" ]]; then
        # index in checkpoint = gap iterations completed (0..enc_count)
        INDEX=$(python3 -c "import json; d=json.load(open('${CHECKPOINT}')); print(d.get('index', 0))" 2>/dev/null || echo "?")
        if [[ "$TOTAL" != "?" && "$INDEX" != "?" && "$TOTAL" -gt 0 ]]; then
            PCT=$(python3 -c "print(f'{100*${INDEX}/${TOTAL}:.1f}')" 2>/dev/null || echo "?")
            printf "progress=%s/%s (%s%%)" "$INDEX" "$TOTAL" "$PCT"
        else
            printf "index=%s / total=%s" "$INDEX" "$TOTAL"
        fi
    else
        printf "not started (no checkpoint)"
    fi

    # Check if still running
    if pgrep -f "run2 ${CONFIG}" > /dev/null 2>&1; then
        printf "  [running]"
    else
        printf "  [stopped]"
    fi

    echo ""
done

echo ""
echo "=== Matches ==="
# Check output.txt and all log files for hits
FOUND=0
for GPU in "${GPUS[@]}"; do
    LOG="${CONFIG_DIR}/gpu${GPU}.log"
    if [[ -f "$LOG" ]]; then
        HITS=$(grep -i "Found at\|Found Match" "$LOG" 2>/dev/null || true)
        if [[ -n "$HITS" ]]; then
            echo "GPU ${GPU}: $HITS"
            FOUND=1
        fi
    fi
done
if [[ -f output.txt ]]; then
    HITS=$(grep -i "Found at\|Found Match" output.txt 2>/dev/null || true)
    if [[ -n "$HITS" ]]; then
        echo "output.txt: $HITS"
        FOUND=1
    fi
fi
if [[ "$FOUND" -eq 0 ]]; then
    echo "  (none yet)"
fi
