#!/usr/bin/env bash
set -euo pipefail

SNAPSHOT_FILE=".storage-layout"
CURRENT=$(forge inspect StateOracle storage-layout 2>&1)

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

# Extract slot assignments (Name + Slot columns) from both layouts
# to detect reordering of existing variables
prev_slots=$(echo "$PREVIOUS" | grep '|' | grep -v 'Name' | grep -v '====' | grep -v '^\+' | awk -F'|' '{gsub(/^ +| +$/, "", $2); gsub(/^ +| +$/, "", $4); if ($2 != "" && $2 != "---") print $2 ":" $4}')
curr_slots=$(echo "$CURRENT" | grep '|' | grep -v 'Name' | grep -v '====' | grep -v '^\+' | awk -F'|' '{gsub(/^ +| +$/, "", $2); gsub(/^ +| +$/, "", $4); if ($2 != "" && $2 != "---") print $2 ":" $4}')

# Check for reordering: any variable that existed before must keep the same slot
reorder_detected=false
while IFS= read -r entry; do
    name="${entry%%:*}"
    old_slot="${entry##*:}"
    new_entry=$(echo "$curr_slots" | grep "^${name}:" || true)
    if [ -n "$new_entry" ]; then
        new_slot="${new_entry##*:}"
        if [ "$old_slot" != "$new_slot" ]; then
            echo "CRITICAL: Variable '$name' moved from slot $old_slot to slot $new_slot!"
            reorder_detected=true
        fi
    fi
done <<< "$prev_slots"

if $reorder_detected; then
    echo ""
    echo "STORAGE SLOT REORDERING DETECTED - This will break existing proxies!"
    echo ""
    echo "Previous layout:"
    echo "$PREVIOUS"
    echo ""
    echo "Current layout:"
    echo "$CURRENT"
    exit 2
fi

echo "Storage layout has changed (but no reordering detected)."
echo ""
echo "Diff:"
diff <(echo "$PREVIOUS") <(echo "$CURRENT") || true
echo ""
echo "If this change is intentional, update the snapshot:"
echo "  forge inspect StateOracle storage-layout > .storage-layout"
exit 1
