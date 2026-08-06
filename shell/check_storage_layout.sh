#!/usr/bin/env bash
set -euo pipefail

SNAPSHOT_FILE=".storage-layout"

# Reported separately from a layout change, so a broken build is never mistaken
# for a benign edit that just needs a snapshot refresh.
if ! RAW=$(forge inspect StateOracle storage-layout --json); then
    echo "ERROR: 'forge inspect StateOracle storage-layout' failed - does the project compile?" >&2
    exit 3
fi

if [ ! -f "$SNAPSHOT_FILE" ]; then
    echo "No .storage-layout snapshot found. Generating..."
    echo "$RAW" > "$SNAPSHOT_FILE"
    echo "Snapshot saved to $SNAPSHOT_FILE"
    exit 0
fi

# solc embeds AST node ids in contract, struct and enum type identifiers and in
# astId. Those ids shift whenever anything earlier in the compilation unit
# changes, so comparing them raw reports storage-safe edits as collisions. They
# carry no storage meaning. Array lengths, which do, are left untouched.
# Entries are sorted by slot so that a reordering of the toolchain's output is
# not mistaken for a layout change.
# The types table is kept because a struct reached through a mapping keeps its
# top-level slot, offset and type id while its members move underneath it. That
# is a real collision that is invisible in .storage alone.
normalize() {
    jq '
        def strip_ids:
            gsub("(?<k>t_(contract|struct|enum|userDefinedValueType)\\([^)]*\\))[0-9]+"; "\(.k)");
        def entry:
            {label, slot, offset, type: (.type | strip_ids)};
        {
            storage: ([.storage[] | entry] | sort_by((.slot | tonumber), .offset, .label)),
            types: (
                (.types // {})
                | with_entries(
                    .key |= strip_ids
                    | .value |= {
                        encoding,
                        numberOfBytes,
                        label: (.label | strip_ids),
                        key: (if has("key") then (.key | strip_ids) else null end),
                        value: (if has("value") then (.value | strip_ids) else null end),
                        base: (if has("base") then (.base | strip_ids) else null end),
                        members: (
                            if has("members") then
                                ([.members[] | entry] | sort_by((.slot | tonumber), .offset, .label))
                            else
                                null
                            end
                        )
                    }
                )
            )
        }
    '
}

# Checked before normalizing, so malformed JSON is diagnosed rather than
# crashing jq. An empty or truncated snapshot would otherwise leave both
# comparison loops with nothing to iterate, reporting a benign change with an
# empty diff. The types table is required too: without it the struct member
# comparison would silently pass on everything.
if ! jq -e '(.storage | type == "array") and (.types | type == "object")' \
    <"$SNAPSHOT_FILE" >/dev/null 2>&1; then
    echo "ERROR: $SNAPSHOT_FILE is not a valid storage layout snapshot." >&2
    echo "Regenerate it with: make update-storage-layout" >&2
    exit 3
fi

CURRENT=$(echo "$RAW" | normalize)
PREVIOUS=$(normalize <"$SNAPSHOT_FILE")

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

# Struct members carry the real layout of everything behind a mapping, so they
# are compared too. Reordering them relocates every deployed record.
# The key queries are captured rather than read from a process substitution,
# whose exit status would be discarded.
if ! struct_types=$(echo "$PREVIOUS" | jq -r '.types | to_entries[] | select(.value.members != null) | .key'); then
    echo "ERROR: could not read the types table from $SNAPSHOT_FILE." >&2
    exit 3
fi

while read -r type_id; do
    [ -n "$type_id" ] || continue

    if [ "$(echo "$CURRENT" | jq --arg t "$type_id" '.types | has($t)')" != "true" ]; then
        echo "WARNING: Type '$type_id' was removed from the layout!"
        collision_detected=true
        continue
    fi

    if ! member_labels=$(echo "$PREVIOUS" | jq -r --arg t "$type_id" '.types[$t].members[].label'); then
        echo "ERROR: could not read the members of '$type_id' from $SNAPSHOT_FILE." >&2
        exit 3
    fi

    while read -r member; do
        [ -n "$member" ] || continue
        old_member=$(echo "$PREVIOUS" | jq -c --arg t "$type_id" --arg m "$member" \
            '.types[$t].members[] | select(.label == $m)')
        new_member=$(echo "$CURRENT" | jq -c --arg t "$type_id" --arg m "$member" \
            '.types[$t].members[] | select(.label == $m)')

        if [ -z "$new_member" ]; then
            echo "WARNING: Member '$type_id.$member' was removed from the layout!"
            collision_detected=true
            continue
        fi

        if [ "$old_member" != "$new_member" ]; then
            echo "CRITICAL: Member '$type_id.$member' moved: $old_member -> $new_member!"
            collision_detected=true
        fi
    done <<<"$member_labels"
done <<<"$struct_types"

if $collision_detected; then
    echo ""
    echo "STORAGE LAYOUT COLLISION DETECTED - This will break existing proxies!"
    echo ""
    diff <(echo "$PREVIOUS" | jq -S '.') <(echo "$CURRENT" | jq -S '.') || true
    exit 2
fi

echo "Storage layout has changed (but no collisions detected)."
echo ""
echo "Diff:"
diff <(echo "$PREVIOUS" | jq -S '.') <(echo "$CURRENT" | jq -S '.') || true
echo ""
echo "If this change is intentional, update the snapshot:"
echo "  forge inspect StateOracle storage-layout --json > .storage-layout"
exit 1
