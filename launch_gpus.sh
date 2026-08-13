#!/usr/bin/env bash
# Launch akira-bruteforce run2 on a set of GPUs in parallel.
#
# Usage:
#   ./launch_gpus.sh <config_dir> <gpu_id> [gpu_id ...]
#
# Example — GPUs 2-7 on tii_cuda_server (0-1 are another tenant):
#   ./launch_gpus.sh search_final 2 3 4 5 6 7
#
# Example — all 8 GPUs on server1/2/4:
#   ./launch_gpus.sh search_final 0 1 2 3 4 5 6 7
#
# Each GPU expects a config file named <config_dir>/gpu<N>.json
# Output is written to <config_dir>/gpu<N>.log
# A match (if found) is also appended to output.txt in the run directory.

set -euo pipefail

if [[ $# -lt 2 ]]; then
    echo "Usage: $0 <config_dir> <gpu_id> [gpu_id ...]"
    exit 1
fi

CONFIG_DIR="$1"; shift
GPUS=("$@")
BINARY="./akira-bruteforce"

if [[ ! -x "$BINARY" ]]; then
    echo "Error: $BINARY not found or not executable. Run 'make' first."
    exit 1
fi

for GPU in "${GPUS[@]}"; do
    CONFIG="${CONFIG_DIR}/gpu${GPU}.json"
    LOG="${CONFIG_DIR}/gpu${GPU}.log"

    if [[ ! -f "$CONFIG" ]]; then
        echo "Warning: config not found for GPU ${GPU}: ${CONFIG} — skipping"
        continue
    fi

    echo "Starting GPU ${GPU}  config=${CONFIG}  log=${LOG}"
    nohup "$BINARY" run2 "$CONFIG" "$GPU" > "$LOG" 2>&1 &
    echo "  PID $!"
done

echo ""
echo "All GPUs launched. Monitor with:"
echo "  ./monitor_gpus.sh ${CONFIG_DIR} ${GPUS[*]}"
