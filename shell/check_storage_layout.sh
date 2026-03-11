#!/usr/bin/env bash
set -euo pipefail

SNAPSHOT_FILE=".storage-layout"
CURRENT=$(forge inspect StateOracle storage-layout --json)

if [ ! -f "$SNAPSHOT_FILE" ]; then
    echo "No .storage-layout snapshot found. Generating..."
    echo "$CURRENT" > "$SNAPSHOT_FILE"
    echo "Snapshot saved to $SNAPSHOT_FILE"
    exit 0
fi

PREVIOUS=$(cat "$SNAPSHOT_FILE")

if [ "$CURRENT" = "$PREVIOUS" ]; then
    echo "Storage layout unchanged."
    exit 0
fi

# Compare each variable that existed in the previous layout against the current one.
# Any change in slot, offset, or type for an existing variable is a breaking change.
collision_detected=false

prev_count=$(echo "$PREVIOUS" | jq '.storage | length')
for i in $(seq 0 $((prev_count - 1))); do
    name=$(echo "$PREVIOUS" | jq -r ".storage[$i].label")
    old_slot=$(echo "$PREVIOUS" | jq -r ".storage[$i].slot")
    old_offset=$(echo "$PREVIOUS" | jq -r ".storage[$i].offset")
    old_type=$(echo "$PREVIOUS" | jq -r ".storage[$i].type")

    # Find the same variable in current layout
    match=$(echo "$CURRENT" | jq -r ".storage[] | select(.label == \"$name\")" 2>/dev/null)
    if [ -z "$match" ]; then
        echo "WARNING: Variable '$name' was removed from storage layout!"
        collision_detected=true
        continue
    fi

    new_slot=$(echo "$match" | jq -r '.slot')
    new_offset=$(echo "$match" | jq -r '.offset')
    new_type=$(echo "$match" | jq -r '.type')

    if [ "$old_slot" != "$new_slot" ]; then
        echo "CRITICAL: Variable '$name' moved from slot $old_slot to slot $new_slot!"
        collision_detected=true
    fi
    if [ "$old_offset" != "$new_offset" ]; then
        echo "CRITICAL: Variable '$name' offset changed from $old_offset to $new_offset in slot $old_slot!"
        collision_detected=true
    fi
    if [ "$old_type" != "$new_type" ]; then
        echo "CRITICAL: Variable '$name' type changed from $old_type to $new_type!"
        collision_detected=true
    fi
done

if $collision_detected; then
    echo ""
    echo "STORAGE LAYOUT COLLISION DETECTED - This will break existing proxies!"
    echo ""
    diff <(echo "$PREVIOUS" | jq '.storage') <(echo "$CURRENT" | jq '.storage') || true
    exit 2
fi

echo "Storage layout has changed (but no collisions detected)."
echo ""
echo "Diff:"
diff <(echo "$PREVIOUS" | jq '.storage') <(echo "$CURRENT" | jq '.storage') || true
echo ""
echo "If this change is intentional, update the snapshot:"
echo "  forge inspect StateOracle storage-layout --json > .storage-layout"
exit 1
