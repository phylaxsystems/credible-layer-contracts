#!/usr/bin/env bash
set -euo pipefail

# Compares the published ABI surface against the committed snapshot in .abi/.
# Entries are keyed by function selector and event topic0, so reordering or
# reformatting by the toolchain never produces a diff.
#
# Pass --update to regenerate the snapshot instead of checking it.
#
# Exit codes:
#   0  ABI unchanged
#   1  ABI changed, but only additively
#   2  ABI compatibility break
#   3  the check could not run

SNAPSHOT_DIR=".abi"

# The contracts published to npm by shell/create_artifacts.sh, plus
# AdminVerifierWhitelist, whose signatures the dapp seed script calls by literal
# string through `cast send` and so cannot break at compile time.
CONTRACTS=(
    StateOracle
    AdminVerifierOwner
    AdminVerifierWhitelist
    DAVerifierECDSA
    IBatch
    IDAVerifier
    IAdminVerifier
    AdminVerifierRegistry
)

# Builds once, so the ABI check never drives compilation itself. `forge inspect`
# would add its own field to the output selection and invalidate the build
# cache, forcing the next `forge build` to recompile every file.
build_once() {
    if ! forge build >/dev/null; then
        echo "ERROR: forge build failed." >&2
        exit 3
    fi
}

# Emits the selector/topic0 fingerprint of one contract's ABI.
# Signatures are canonical: contract and enum parameters collapse to their
# underlying ABI type, so renaming an interface does not shift a hash.
abi_fingerprint() {
    local contract=$1
    local artifact abi rows kind signature indexed anonymous mutability outputs hash
    artifact="out/$contract.sol/$contract.json"

    # set -e does not abort a function running inside a command substitution, so
    # every failure below is checked explicitly. Without this a missing artifact
    # yields an empty ABI, which would be misreported as "everything removed".
    if [ ! -f "$artifact" ]; then
        echo "ERROR: no build artifact at $artifact." >&2
        return 1
    fi

    if ! abi=$(jq -c '.abi' "$artifact"); then
        echo "ERROR: could not read the ABI from $artifact." >&2
        return 1
    fi

    if [ "$(echo "$abi" | jq -r 'type' 2>/dev/null || true)" != "array" ]; then
        echo "ERROR: $artifact does not contain an ABI array." >&2
        return 1
    fi

    # Fields are joined with US (0x1f) rather than tabs: tab is IFS whitespace,
    # so `read` would coalesce runs of them and silently drop empty fields,
    # shifting every later field left for zero-argument entries.
    if ! rows=$(echo "$abi" | jq -r '
        def canon:
            if (.type | startswith("tuple")) then
                "(" + ((.components // []) | map(canon) | join(",")) + ")" + (.type | ltrimstr("tuple"))
            else
                .type
            end;
        .[]
        | select(.type == "function" or .type == "event" or .type == "error")
        | [
            .type,
            (.name + "(" + ((.inputs // []) | map(canon) | join(",")) + ")"),
            ((.inputs // []) | map(if .indexed then "1" else "0" end) | join("")),
            (if .anonymous then "true" else "false" end),
            (.stateMutability // ""),
            ((.outputs // []) | map(canon) | join(","))
        ]
        | join("\u001f")
    '); then
        echo "ERROR: could not read the ABI entries of $contract." >&2
        return 1
    fi

    while IFS=$'\x1f' read -r kind signature indexed anonymous mutability outputs; do
        [ -n "$kind" ] || continue
        if ! hash=$(cast keccak "$signature"); then
            echo "ERROR: 'cast keccak' failed for '$signature'." >&2
            exit 1
        fi
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$kind" "$hash" "$signature" "$indexed" "$anonymous" "$mutability" "$outputs"
    done <<<"$rows" | jq -S -R -s --arg contract "$contract" '
        [splits("\n") | select(length > 0) | [splits("\t")]] as $rows
        | {
            contract: $contract,
            functions: (
                $rows | map(select(.[0] == "function"))
                | map({key: .[1][0:10], value: {signature: .[2], stateMutability: .[5], outputs: .[6]}})
                | from_entries
            ),
            events: (
                $rows | map(select(.[0] == "event"))
                | map({key: .[1], value: {signature: .[2], indexed: .[3], anonymous: (.[4] == "true")}})
                | from_entries
            ),
            errors: (
                $rows | map(select(.[0] == "error"))
                | map({key: .[1][0:10], value: {signature: .[2]}})
                | from_entries
            )
        }
    '
}

write_snapshot() {
    build_once
    mkdir -p "$SNAPSHOT_DIR"
    local contract tmp
    for contract in "${CONTRACTS[@]}"; do
        # Written beside the target so a failed run never truncates the snapshot.
        tmp="$SNAPSHOT_DIR/.$contract.json.tmp"
        if ! abi_fingerprint "$contract" >"$tmp"; then
            rm -f "$tmp"
            exit 3
        fi
        mv "$tmp" "$SNAPSHOT_DIR/$contract.json"
        echo "Wrote $SNAPSHOT_DIR/$contract.json"
    done
    echo "ABI snapshot updated."
}

if [ "${1:-}" = "--update" ]; then
    write_snapshot
    exit 0
fi

if [ ! -d "$SNAPSHOT_DIR" ]; then
    echo "No $SNAPSHOT_DIR snapshot found. Generating..."
    write_snapshot
    exit 0
fi

build_once

removed_keys() {
    jq -r -n --argjson a "$1" --argjson b "$2" --arg s "$3" \
        '($a[$s] | keys) - ($b[$s] | keys) | .[]'
}

common_keys() {
    jq -r -n --argjson a "$1" --argjson b "$2" --arg s "$3" \
        '$a[$s] | keys[] | select(. as $k | $b[$s] | has($k))'
}

# A process substitution discards its exit status, so each key query below is
# captured and checked instead. A malformed snapshot would otherwise read as an
# empty key set, and the check would conclude that nothing was added or removed.
snapshot_error() {
    echo "ERROR: could not compare '$1' against its snapshot - it may be malformed." >&2
    echo "Regenerate it with: make update-abi" >&2
    exit 3
}

# Reports whether state mutability moved in a direction that breaks callers.
# Losing staticcall-ability breaks eth_call consumers; losing payable breaks
# callers that send value. The reverse of either is safe.
mutability_change() {
    local before=$1 after=$2
    local static_before=false static_after=false
    local payable_before=false payable_after=false

    if [ "$before" = "view" ] || [ "$before" = "pure" ]; then static_before=true; fi
    if [ "$after" = "view" ] || [ "$after" = "pure" ]; then static_after=true; fi
    if [ "$before" = "payable" ]; then payable_before=true; fi
    if [ "$after" = "payable" ]; then payable_after=true; fi

    if { $static_before && ! $static_after; } || { $payable_before && ! $payable_after; }; then
        echo "tightened"
    elif { ! $static_before && $static_after; } || { ! $payable_before && $payable_after; }; then
        echo "relaxed"
    else
        echo "same"
    fi
}

# A function or event is reachable only through its selector/topic0, so a
# caller breaks the moment a key disappears. Renames, retypes and most reorders
# surface here as a removal, because each of them changes the hash. Swapping two
# parameters of the same type does not: the canonical signature is unchanged, so
# no selector-based check can see it.
breaking=false
additive=false

for contract in "${CONTRACTS[@]}"; do
    snapshot_file="$SNAPSHOT_DIR/$contract.json"

    if ! current=$(abi_fingerprint "$contract"); then
        exit 3
    fi

    if [ ! -f "$snapshot_file" ]; then
        echo "NOTE: '$contract' has no snapshot yet - it is newly in scope."
        additive=true
        continue
    fi

    if ! previous=$(cat "$snapshot_file"); then
        snapshot_error "$contract"
    fi

    if [ "$current" = "$previous" ]; then
        continue
    fi

    for section in functions events errors; do
        if ! gone=$(removed_keys "$previous" "$current" "$section"); then
            snapshot_error "$contract"
        fi
        while read -r key; do
            [ -n "$key" ] || continue
            signature=$(echo "$previous" | jq -r --arg k "$key" --arg s "$section" '.[$s][$k].signature')
            echo "CRITICAL: $contract: $section entry '$signature' ($key) was removed or its hash changed!"
            breaking=true
        done <<<"$gone"

        if ! added=$(removed_keys "$current" "$previous" "$section"); then
            snapshot_error "$contract"
        fi
        while read -r key; do
            [ -n "$key" ] || continue
            signature=$(echo "$current" | jq -r --arg k "$key" --arg s "$section" '.[$s][$k].signature')
            echo "NOTE: $contract: new $section entry '$signature' ($key)."
            additive=true
        done <<<"$added"
    done

    # topic0 does not cover indexedness, so an indexed flip keeps the same key
    # while moving a field between topics and data. Historical decoders break
    # silently on exactly this change, so it is compared separately.
    if ! shared_events=$(common_keys "$previous" "$current" events); then
        snapshot_error "$contract"
    fi
    while read -r key; do
        [ -n "$key" ] || continue
        signature=$(echo "$previous" | jq -r --arg k "$key" '.events[$k].signature')
        old_indexed=$(echo "$previous" | jq -r --arg k "$key" '.events[$k].indexed')
        new_indexed=$(echo "$current" | jq -r --arg k "$key" '.events[$k].indexed')
        old_anonymous=$(echo "$previous" | jq -r --arg k "$key" '.events[$k].anonymous')
        new_anonymous=$(echo "$current" | jq -r --arg k "$key" '.events[$k].anonymous')

        if [ "$old_indexed" != "$new_indexed" ]; then
            echo "CRITICAL: $contract: event '$signature' indexed layout changed from $old_indexed to $new_indexed!"
            breaking=true
        fi
        if [ "$old_anonymous" != "$new_anonymous" ]; then
            echo "CRITICAL: $contract: event '$signature' anonymous changed from $old_anonymous to $new_anonymous!"
            breaking=true
        fi
    done <<<"$shared_events"

    if ! shared_functions=$(common_keys "$previous" "$current" functions); then
        snapshot_error "$contract"
    fi
    while read -r key; do
        [ -n "$key" ] || continue
        signature=$(echo "$previous" | jq -r --arg k "$key" '.functions[$k].signature')
        old_mutability=$(echo "$previous" | jq -r --arg k "$key" '.functions[$k].stateMutability')
        new_mutability=$(echo "$current" | jq -r --arg k "$key" '.functions[$k].stateMutability')
        old_outputs=$(echo "$previous" | jq -r --arg k "$key" '.functions[$k].outputs')
        new_outputs=$(echo "$current" | jq -r --arg k "$key" '.functions[$k].outputs')

        # The selector covers only the inputs, so a changed return type or arity
        # keeps the same key while breaking every eth_call decoder.
        if [ "$old_outputs" != "$new_outputs" ]; then
            echo "CRITICAL: $contract: function '$signature' return types changed from ($old_outputs) to ($new_outputs)!"
            breaking=true
        fi

        if [ "$old_mutability" != "$new_mutability" ]; then
            case "$(mutability_change "$old_mutability" "$new_mutability")" in
            tightened)
                echo "CRITICAL: $contract: function '$signature' mutability tightened from $old_mutability to $new_mutability!"
                breaking=true
                ;;
            *)
                echo "NOTE: $contract: function '$signature' mutability relaxed from $old_mutability to $new_mutability."
                additive=true
                ;;
            esac
        fi
    done <<<"$shared_functions"
done

if $breaking; then
    echo ""
    echo "ABI COMPATIBILITY BREAK DETECTED - This will break off-chain callers and log decoders!"
    echo ""
    echo "If this change is intentional, update the snapshot:"
    echo "  make update-abi"
    exit 2
fi

if $additive; then
    echo ""
    echo "ABI has changed (but only additively)."
    echo ""
    echo "Refresh the snapshot so later removals are still caught:"
    echo "  make update-abi"
    exit 1
fi

echo "ABI unchanged."
exit 0
