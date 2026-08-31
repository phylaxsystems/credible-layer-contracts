# Releasing the Rust bindings

Tagged releases publish the Cargo crate through crates.io trusted publishing.
The workflow requests a short-lived token with GitHub OIDC; do not add a
long-lived crates.io token to the repository's Actions secrets.

## One-time crates.io bootstrap

crates.io requires the crate to exist before a trusted publisher can be
registered. Bootstrap the first release from the same commit that will be
tagged:

1. Sign in to crates.io with GitHub and verify the publishing account's email.
2. Create a narrowly scoped crates.io API token.
3. Run `./shell/bump-version.sh patch` to update both package versions and
   create the local release tag.
4. Run `cargo login`, then
   `cargo publish --manifest-path bindings/rust/Cargo.toml`.
5. In the new crate's trusted-publishing settings, register GitHub owner
   `phylaxsystems`, repository `credible-layer-contracts`, workflow
   `release.yml`, and no GitHub environment.
6. Revoke the bootstrap API token (and run `cargo logout` locally).
7. Push the version commit and its tag. The workflow recognizes that the
   bootstrap version already exists; later tags publish automatically via OIDC.

## Normal releases

Use `./shell/bump-version.sh patch|minor|major`, review the resulting commit and
tag, then push both. The release fails before publishing if the npm version,
Cargo version, tag, or committed versioned interface ABI disagree.
