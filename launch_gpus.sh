#!/usr/bin/env bash
# Launch akira-bruteforce run2 on a set of GPUs in parallel.
#
# Usage:
#   ./launch_gpus.sh <config_dir> <gpu_id[:config_id]> [gpu_id[:config_id] ...]
#
# Example — GPUs 2-7 on tii_cuda_server (0-1 are another tenant):
#   ./launch_gpus.sh search_final 2:0 3:1 4:2 5:3 6:4 7:5
#
# Example — all 8 GPUs on server1/2/4:
#   ./launch_gpus.sh search_final 0 1 2 3 4 5 6 7
#
# A mapping such as 2:0 runs logical slice gpu0.json on physical GPU 2.
# When config_id is omitted, it defaults to gpu_id.
# Output is written to <config_dir>/gpu<physical>-slice<logical>.log
# A match (if found) is also appended to output.txt in the run directory.

set -euo pipefail

if [[ $# -lt 2 ]]; then
    echo "Usage: $0 <config_dir> <gpu_id[:config_id]> [gpu_id[:config_id] ...]"
    exit 1
fi

CONFIG_DIR="$1"; shift
MAPPINGS=("$@")
BINARY="./akira-bruteforce"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ! -x "$BINARY" ]]; then
    echo "Error: $BINARY not found or not executable. Run 'make' first."
    exit 1
fi

parse_mapping() {
    local mapping="$1"
    if [[ "$mapping" == *:* ]]; then
        GPU="${mapping%%:*}"
        CONFIG_ID="${mapping#*:}"
    else
        GPU="$mapping"
        CONFIG_ID="$mapping"
    fi
}

# Validate the complete plan before starting any process.
USED_GPUS=" "
USED_CONFIGS=" "
for MAPPING in "${MAPPINGS[@]}"; do
    parse_mapping "$MAPPING"
    if ! [[ "$GPU" =~ ^[0-9]+$ && "$CONFIG_ID" =~ ^[0-9]+$ ]]; then
        echo "Error: invalid mapping '$MAPPING'; expected physical_gpu:logical_config"
        exit 1
    fi
    if [[ "$USED_GPUS" == *" $GPU "* || "$USED_CONFIGS" == *" $CONFIG_ID "* ]]; then
        echo "Error: duplicate physical GPU or logical config in mapping '$MAPPING'"
        exit 1
    fi
    USED_GPUS+="$GPU "
    USED_CONFIGS+="$CONFIG_ID "

    CONFIG="${CONFIG_DIR}/gpu${CONFIG_ID}.json"
    if [[ ! -f "$CONFIG" ]]; then
        echo "Error: config not found for mapping ${MAPPING}: ${CONFIG}"
        exit 1
    fi
done

for MAPPING in "${MAPPINGS[@]}"; do
    parse_mapping "$MAPPING"
    CONFIG="${CONFIG_DIR}/gpu${CONFIG_ID}.json"
    LOG="${CONFIG_DIR}/gpu${GPU}-slice${CONFIG_ID}.log"

    echo "Starting physical GPU ${GPU} with logical slice ${CONFIG_ID}  config=${CONFIG}  log=${LOG}"
    nohup "$BINARY" run2 "$CONFIG" "$GPU" > "$LOG" 2>&1 &
    echo "  PID $!"
done

echo ""
echo "All GPUs launched. Monitor with:"
echo "  ${SCRIPT_DIR}/monitor_gpus.sh ${CONFIG_DIR} ${MAPPINGS[*]}"
