#!/usr/bin/env bash

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

# Stage the package.json changes
git add package.json

# Commit the version bump
git commit -m "chore: bump version to ${TAG_NAME}"

# Create and push the new tag
git tag "${TAG_NAME}"

echo "✅ Successfully:"
echo "  - Bumped npm version to ${TAG_NAME}"
echo "  - Created git tag ${TAG_NAME}"
echo ""
echo "To push changes:"
echo "  git push origin ${TAG_NAME}" 