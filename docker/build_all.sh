#!/bin/bash
# docker/build_all.sh
# Builds one Docker image per bug per scenario.
# Run from the Smite repo root: bash smite-evaluation/docker/build_all.sh

set -euo pipefail

EVAL_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SMITE_DIR="$(cd "$EVAL_DIR/.." && pwd)"
DOCKER_DIR="$EVAL_DIR/docker"
VULNS_DIR="$EVAL_DIR/vulnerabilities"

# Scenarios to build. Add more if needed for ablation.
SCENARIOS=("encrypted_bytes" "ir")

# Apply stdio-inherit patch so target stderr is visible during local reproduction.
# git apply is idempotent here: the || true silences the expected failure
# on subsequent runs when the patch is already applied.
git -C "$SMITE_DIR" apply "$EVAL_DIR/docker/stdio-inherit.patch" 2>/dev/null || true

for meta_file in "$VULNS_DIR"/*/*/metadata.json; do
    target=$(python3 -c "import json,sys; print(json.load(open('$meta_file'))['target'])")
    cve=$(python3 -c "import json,sys; print(json.load(open('$meta_file'))['cve'])")
    commit=$(python3 -c "import json,sys; print(json.load(open('$meta_file'))['buggy_commit'])")
    patch=""
    if [ -s "$VULNS_DIR/$target/$cve/flag.patch" ]; then
        patch="${target}/${cve}/flag.patch"
    fi

    for scenario in "${SCENARIOS[@]}"; do
        image="smite-eval-${target}-${cve,,}-${scenario}"

        if docker image inspect "$image" > /dev/null 2>&1; then
            echo "[skip] $image already exists"
            continue
        fi

        echo "[build] $image"
        
        # Branch build args depending on whether target is LDK or not
        if [ "$target" = "ldk" ]; then
            docker build \
                -t "$image" \
                -f "$DOCKER_DIR/${target}.Dockerfile" \
                --build-arg "SCENARIO=$scenario" \
                --build-arg "SMITE_PATCH=${target}/${cve}/smite.patch" \
                --build-arg "FLAG_PATCH=$patch" \
                "$SMITE_DIR"
        else
            docker build \
                -t "$image" \
                -f "$DOCKER_DIR/${target}.Dockerfile" \
                --build-arg "SCENARIO=$scenario" \
                --build-arg "COMMIT_HASH=$commit" \
                --build-arg "FLAG_PATCH=$patch" \
                "$SMITE_DIR"
        fi
    done
done

echo "All images built."

# Build the custom mutator
echo "Building custom mutator..."
cargo build --release -p smite-ir-mutator

# Enable KVM-backdoor for Nyx
echo "Enabling VMware backdoor..."
sudo "$SMITE_DIR/scripts/enable-vmware-backdoor.sh"