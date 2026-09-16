#!/usr/bin/env bash

set -euo pipefail

# Check if an argument was provided
if [ $# -ne 1 ]; then
    echo "Usage: $0 <patch|minor|major>"
    echo "Example: $0 patch"
    exit 1
fi

# Validate the argument
VERSION_TYPE=$1
if [[ ! "$VERSION_TYPE" =~ ^(patch|minor|major)$ ]]; then
    echo "Error: Version type must be 'patch', 'minor', or 'major'"
    exit 1
fi

# Ensure we're in a clean git state
if [[ -n $(git status --porcelain) ]]; then
    echo "Error: Working directory is not clean. Please commit or stash changes first."
    exit 1
fi

# Run npm version and capture the output
NEW_VERSION=$(npm version "$VERSION_TYPE" --no-git-tag-version)

# Strip the leading 'v' from the version
TAG_NAME=${NEW_VERSION#v}

# Keep the Cargo package on the same release train as the npm package and tag.
sed -i.bak \
    "s/^version = \"[0-9][0-9.]*\"$/version = \"${TAG_NAME}\"/" \
    bindings/rust/Cargo.toml
rm bindings/rust/Cargo.toml.bak

# Stage the package metadata changes
git add package.json bindings/rust/Cargo.toml

# Commit the version bump
git commit -m "chore: bump version to ${TAG_NAME}"

# Create and push the new tag
git tag "${TAG_NAME}"

echo "✅ Successfully:"
echo "  - Bumped npm and Cargo versions to ${TAG_NAME}"
echo "  - Created git tag ${TAG_NAME}"
echo ""
echo "To push changes:"
echo "  git push origin HEAD"
echo "  git push origin ${TAG_NAME}"
