# StateOracle V2 Architecture, Roles, and Invariants

This document is the repository reference for `StateOracleV2`. It explains the authority model, stored state, lifecycle rules, and invariants that changes to the contract must preserve. It applies to fresh V2 deployments; V1 has a different manager, whitelist, and quota model.

The Solidity contracts and tests are authoritative if this document ever disagrees with the implementation. Architectural changes should update all three together.

## Mental model

- A **project** is the on-chain sibling of one platform project. It has one aggregate trigger-unit limit and zero or more assertion adopters.
- An **assertion adopter** is a contract address. It may be assigned to at most one project at a time within one StateOracle instance.
- A **protocol manager** is stored on a project and operates every adopter assigned to that project. It is not an AccessControl role.
- An **assertion installation** is keyed by `(assertionAdopter, assertionId)`. Installing the same assertion on two adopters creates two installations and consumes trigger units twice.
- The **assertion ID** is `deploymentCodeHash`. The trigger manifest configures an installation but is deliberately excluded from assertion identity.
- There is no caller whitelist and no per-adopter assertion limit in V2. Capacity is controlled by each project's trigger-unit limit.

The platform should generate and persist a random nonzero `bytes32` project ID before submitting `createProject`. The contract enforces only that the ID is nonzero and has never been used. Retired IDs remain tombstoned and cannot be reused.

## Roles and actors

The AccessControl roles are deliberately narrow. Deployments may initially grant several roles to one multisig, but the contract keeps them independently revocable so they can later be separated without an upgrade.

| Role or actor | Why it exists | Authority | Authority it deliberately does not have |
| --- | --- | --- | --- |
| Owner / `DEFAULT_ADMIN_ROLE` | Root security administration and recovery of compromised operational role holders. | Administers role membership and owns the oracle application contract. Ownership acceptance moves `DEFAULT_ADMIN_ROLE` and any V2 operational roles still held by the old owner to the new owner. | The owner is not an implicit superuser for oracle operations; it must also hold the relevant operational role. It is not necessarily the `TransparentUpgradeableProxy` administrator and should not perform routine project operations. |
| `GOVERNANCE_ROLE` | Protocol-wide configuration with the highest operational security assumption. | Pause and unpause; add or remove admin verifiers and DA verifiers; add or replace trigger-manifest validators. | No project creation, project-specific manager recovery, trigger-limit changes, adopter operations, assertion operations, or retirement. |
| `GUARDIAN_ADMIN_ROLE` | Isolates guardian membership administration from other root operations. | Grant and revoke `GUARDIAN_ROLE`. | No guardian action unless the account separately holds `GUARDIAN_ROLE`. |
| `GUARDIAN_ROLE` | Reduce assertion-executor load and contain a compromised project quickly. | Remove installed assertions; atomically clear a project's current and pending protocol managers and invalidate its retirement request. | Cannot select a replacement manager, detach adopters, change limits, configure registries, or retire a project. |
| `PROJECT_CREATOR_ROLE` | Allows a comparatively low-trust platform service to automate project creation. A compromised key can create empty projects but cannot take over an existing one. | Create a unique project and set its initial nonzero protocol manager. The project starts with a zero trigger limit. | No authority over an existing project. |
| `PROJECT_ADMIN_ROLE` | Project-specific recovery and retirement finality without giving Governance routine project authority. | Nominate a replacement manager only after Guardian has cleared both manager fields; finalize a manager-requested retirement after trigger usage reaches zero. | Cannot clear a manager, initiate retirement, change limits, detach or reassign adopters, or operate assertions. |
| `TRIGGER_LIMIT_ROLE` | Separates financial/capacity administration from project recovery. | Set an active project's trigger-unit limit, including zero or a value below current usage. | Cannot create or retire projects, recover managers, or operate adopters and assertions. |
| Protocol manager | Routine authority scoped to one project. The address is stored in `Project`, not granted globally. | Accept or reject adopter assignment requests; detach zero-count adopters from an active project; add and remove assertions; reset executor storage; propose a normal manager transfer; request or cancel retirement. | Cannot set limits, finalize retirement, configure registries, or recover itself after Guardian clears it. |
| Verified adopter admin | Represents one contract's intent to join a project without granting ongoing project authority to a key the adopter may not secure long term. | Request assignment to an active project and cancel a pending request after passing a registered `IAdminVerifier`. | Cannot accept the assignment, detach an active assignment, or operate assertions. |
| Permissionless cleanup caller | Ensures terminal project state cannot trap an adopter behind a manager that no longer exists. | Reject a pending assignment targeting a retired project; detach a zero-count adopter still associated with a retired project. | Cannot mutate an active or quarantined project. |

### Role administration

- `DEFAULT_ADMIN_ROLE` administers Governance, Guardian Admin, Project Creator, Project Admin, and Trigger Limit roles.
- `GUARDIAN_ADMIN_ROLE` administers `GUARDIAN_ROLE`.
- `DEFAULT_ADMIN_ROLE` cannot be granted directly. It follows ownership.
- The current owner cannot revoke or renounce its own `DEFAULT_ADMIN_ROLE`; ownership and default administration remain coupled. Renouncing ownership intentionally clears both usable authorities.
- `initialize` grants the initial admin all six operational roles. Production deployment must explicitly hand them to the intended authorities.

Holding a role never removes the normal rules for permissionless functions. For example, a Governance account may clean up a retired adopter, but Governance grants no special power to do so while the project is active.

## Pause and emergency behavior

Pause is an additive/routine-operations circuit breaker, not a total freeze. Recovery and load-reducing paths must remain usable during an incident.

| Blocked while paused | Still available while paused |
| --- | --- |
| Create a project | Guardian manager revocation and assertion removal |
| Request a normal manager transfer | Project Admin recovery nomination |
| Accept a normal transfer while a current manager exists | Accept a recovery nomination while the current manager is zero |
| Request or accept adopter assignment | Protocol-manager assertion removal |
| Add an assertion | Set a project trigger limit |
| Reset executor storage | Finalize a valid zero-usage retirement |
| Request or cancel retirement | Cancel or reject pending adopter registration |
|  | Detach a zero-count adopter under the normal active/retired authorization rule |
|  | Governance registry configuration and unpause |

`batch` is permissionless and has no independent pause check. Each delegated function applies its own authorization and pause rule, so batching cannot bypass this matrix.

## Stored types

### `ProjectStatus`

| Value | Meaning |
| --- | --- |
| `None` | The project ID has never been created. |
| `Active` | The project exists. It may be healthy, in a normal transfer, managerless, or awaiting recovery acceptance. |
| `Retired` | Terminal tombstone. The project ID cannot be recreated. |

### `Project`

| Field | Meaning |
| --- | --- |
| `protocolManager` | Current routine project authority. Zero on a managerless active project and after retirement. |
| `pendingProtocolManager` | Nominee for either a normal transfer or manager recovery. During normal transfer both manager fields are nonzero; during recovery only the pending field is nonzero. |
| `triggerLimit` | Maximum trigger units admitted for new installations. It is a `uint64` and starts at zero. |
| `usedTriggerUnits` | Sum of the stored units of every enabled installation assigned to this project. It is accounting state, not a count of assertions. |
| `retiredAtBlock` | Immediate finalization block for the tombstone, not a timelocked effective block. Zero before retirement. |
| `status` | `None`, `Active`, or `Retired`. |

An active project with `protocolManager == address(0)` is **quarantined**, not retired. Guardian revocation leaves assignments, assertions, limits, and usage intact.

### `AssertionAdopter`

| Field | Meaning |
| --- | --- |
| `projectId` | Current project association. It may temporarily name a retired project until permissionless cleanup detaches it. |
| `pendingProjectId` | Requested target project awaiting manager acceptance. A current and pending project cannot coexist. |
| `assertionCount` | Number of enabled oracle installations for the adopter. It excludes removed installations even while their executor deactivation timelock is still running. |

There is no reverse on-chain project-to-adopter collection. Indexers enumerate projects, adopters, and assertions from events and reconcile entries through the public mappings.

### Assertion submission structs

| Struct | Fields | Meaning |
| --- | --- | --- |
| `TriggerManifest` | `schemaId`, `data` | First-class executor configuration. `schemaId` selects a registered validator; `data` is the canonical schema payload. It is not signed or incorporated into the assertion ID. |
| `AssertionArtifact` | `deploymentCodeHash`, `triggerManifest` | The deployment code hash is the assertion ID. The artifact carries the manifest used for this installation. |
| `DAProof` | `verifier`, `metadata`, `proof` | Selects a registered DA verifier and supplies its verifier-specific inputs. DA proves deployment-payload availability only; it does not attest that the manifest matches bytecode or `triggers()`. |

Bounds enforced by the oracle are 65,536 bytes for manifest data, 65,536 bytes for DA proof, and 4,096 bytes each for DA metadata and admin-verifier data.

Manifest validators return both trigger count and trigger units. StateOracle V2 deliberately discards the raw count and accounts only the returned nonzero `uint64` units.

### `AssertionInstallation`

| Field | Meaning |
| --- | --- |
| `triggerUnits` | Units priced by the manifest validator when this installation was added. Later weight changes do not alter the stored value. |
| `manifestSchemaId` | Schema used to validate the installed manifest. |
| `manifestHash` | `keccak256` of the installed manifest data. The full manifest is emitted, not stored. |
| `enabled` | Immediate oracle state. Removal sets it to false before executor deactivation becomes effective. |

Disabled mapping entries retain the last installation's units, schema, and hash. Re-adding the same `(adopter, assertionId)` in a later transaction overwrites that record with a new installation and newly priced units.

`hasAssertion(adopter, assertionId)` reports this immediate `enabled` flag. It does not answer whether that generation is currently effective in the executor.

### Auxiliary state

- `projectRetirementRequesters[projectId]` stores the manager that requested retirement. Manager acceptance or Guardian revocation clears a stale request.
- `adminVerifiers` and `daVerifiers` are Governance-managed registries.
- `triggerManifestValidators[schemaId]` selects the validator and pricing policy for a manifest schema.
- Activation, deactivation, and storage-reset effective blocks are carried only in events. They are not stored in assertion mappings.

Registry changes affect future calls only. Removing a verifier does not invalidate an existing assignment or installation, and replacing a manifest validator does not revalidate or reprice an installed assertion. A manifest validator can be replaced but not cleared to the zero address.

## Lifecycle rules

### Protocol manager

1. Project Creator installs the initial manager at project creation.
2. For a normal transfer, the current manager proposes a nonzero nominee and the nominee accepts.
3. During an incident, Guardian clears both manager fields and any retirement request. The project becomes managerless but remains active.
4. Project Admin may nominate a replacement only from that fully cleared state. The nominee must accept before receiving authority.
5. Guardian may clear an incorrect recovery nominee and restart the recovery flow.

A retirement request records intent rather than freezing the project. The manager may continue normal operations, and a pending transfer may coexist with the request. Manager acceptance or Guardian quarantine invalidates the request; finalization still requires the requester to be the current manager and usage to be zero.

A current manager may replace an existing normal-transfer nominee by proposing another valid address. There is no separate function that only cancels a pending manager nomination.

### Adopter assignment and movement

1. A registered admin verifier confirms the caller is an admin of an unassigned adopter.
2. The verified admin requests an active project.
3. The target protocol manager accepts or rejects the request; the verified admin may cancel it.
4. To move an active adopter, its assertions must first be removed, the old manager must detach it, and the verified admin must start a fresh request to the new project.
5. If the old project is retired, anyone may detach the zero-count adopter. A pending request targeting a retired project is likewise permissionlessly rejectable.

There is intentionally no Project Admin or Governance shortcut that chooses an adopter's destination project.

The pending assignment stores no verifier identity. Cancellation may use any currently registered verifier that approves the caller; it need not reuse the verifier from the original request.

### Assertion installation

Addition performs the following logical checks:

1. The caller is the assigned active project's protocol manager.
2. The assertion ID is nonzero and that installation is not enabled.
3. Payload bounds pass and the manifest schema has a registered validator.
4. The validator accepts the manifest and returns nonzero trigger units.
5. A registered DA verifier accepts the deployment-code hash and proof.
6. After all external verification calls return, the oracle reads current project usage and requires `usedTriggerUnits + triggerUnits <= triggerLimit`.
7. The oracle enables the installation, increments adopter count and project usage, and emits the full executor payload.

Removal immediately disables the installation and releases its count and units in oracle storage. Its executor deactivation occurs at the emitted effective block.

## System invariants

### Safety and accounting

1. **Owner/default-admin coupling:** effective `DEFAULT_ADMIN_ROLE` authority follows `owner()`; ownership transfer moves both authorities together, and neither can be transferred independently.
2. **Unique project identity:** a nonzero project ID moves only `None -> Active -> Retired`. Retirement is final and leaves a tombstone.
3. **Single adopter assignment:** an adopter has at most one current project and cannot have both current and pending assignments. Reassignment never overwrites an existing association.
4. **Enabled-installation ownership:** every enabled assertion belongs to an adopter assigned to an active project.
5. **Safe detach:** an adopter cannot detach while `assertionCount != 0`.
6. **Count conservation:** each adopter's `assertionCount` equals its number of enabled assertion installations.
7. **Per-project trigger conservation:** `project.usedTriggerUnits` equals the sum of stored units for all enabled installations belonging to its assigned adopters.
8. **Global trigger conservation:** the total units of all enabled installations equals the sum of `usedTriggerUnits` across all projects. There is no trigger usage outside project accounting.
9. **Current-state admission:** trigger capacity is checked after manifest and DA external calls against current stored usage, and accepted units are added to that current value. An external verifier cannot cause a stale absolute usage value to overwrite intervening accounting.
10. **Nonzero installations:** every enabled installation has nonzero stored units. Consequently, the zero usage required for retirement also means no enabled assertion remains in the project.
11. **Grandfathered limit reduction:** lowering a limit never removes existing coverage. Usage may exceed the new limit, but every new addition remains blocked until current usage plus the new installation fits. Therefore `usedTriggerUnits <= triggerLimit` is deliberately **not** a permanent invariant.
12. **Terminal retirement state:** retirement requires a request from the current manager and Project Admin finalization at zero usage. It clears managers, pending manager, retirement request, and limit; records the retirement block; and cannot be reversed.

### Intentional non-invariants

- `usedTriggerUnits <= triggerLimit` is not always true because limit reductions grandfather existing installations. The corresponding global inequality between total usage and total limits is also not an invariant.
- An active project does not always have a manager. Guardian quarantine deliberately creates a managerless active state.
- `usedTriggerUnits` is not instantaneous executor load. Units are reserved before activation and released before timelocked deactivation.
- On-chain accounting does not prove that declared manifest triggers equal the triggers implemented by assertion bytecode. DA proves payload availability, while fail-early tooling and the executor handle manifest/bytecode mismatches.
- An oracle-enabled installation is not guaranteed to become executor-effective if downstream validation rejects or ignores invalid configuration.
- Assertion identity is not globally unique to one adopter or one generation. The same ID may be installed on multiple adopters and reinstalled after removal.
- One transaction is not limited to one executor event. Only repeated mutation of the same logical tuple is prohibited.

### Recoverability and no-stuck constraints

- A zero-count adopter in a healthy active project can be detached by its protocol manager.
- A managerless active project remains recoverable through Guardian clearing, Project Admin nomination, and nominee acceptance. The recovered manager can detach zero-count adopters.
- Guardian can clear a bad recovery nominee so Project Admin can nominate again.
- A zero-count adopter associated with a retired project can be detached by anyone, and anyone can reject a pending request targeting a retired project.
- A new destination always requires a fresh verified-admin request and target-manager acceptance. Recovery authorities never choose it unilaterally.
- These paths prevent permanent trapping while the root, Guardian, Project Admin, and a viable replacement manager remain available. A contract cannot guarantee liveness if every recovery authority is unavailable.

### Executor and event-consumer invariants

- **Immediate storage, delayed execution:** add/remove changes oracle storage immediately. `AssertionAdded`, `AssertionRemoved`, and `StorageReset` carry an effective block of `block.number + ASSERTION_TIMELOCK_BLOCKS` for the executor.
- **Exclusive deactivation boundary:** an old generation is effective before its deactivation block and inactive at that block. Activation begins at the activation block.
- **Installed is not executor-effective:** a detached adopter or newly retired project may still have a removed generation effective until its deactivation boundary. It is no longer an enabled oracle installation and consumes no on-chain trigger units.
- **Per-key transaction guard:** at most one event may be emitted for `(StoreType, adopter, key)` in one transaction. Assertion add/remove share `AssertionLifecycle` with `assertionId` as the key; resets use `StorageReset` with `storageKey`. Different adopters, keys, and store types may coexist in one transaction.
- **Reset plus lifecycle is valid:** a reset and an assertion add/remove may be emitted together, even when their `bytes32` values are equal, because their store types differ.
- **Later-transaction re-add:** a removed assertion may be re-added in any later transaction, including another transaction in the same block. Consumers must preserve successive generations and apply logs in canonical log-index order.
- **Event identity and replay:** consumers must retain every event by its exact canonical block/transaction/log position, process log order without collapsing entries, and make replay idempotent.
- **Same-block continuity:** removal and re-addition in separate transactions in the same block have the same effective boundary. Log order makes the removal precede the new activation, preserving continuous coverage. A next-block re-addition creates a one-block gap.
- **Atomic batching:** `batch` uses self-`delegatecall`; all calls share the sender, storage, and transient event guard, and any inner failure rolls back the whole batch.

The target chain must support Cancun/EIP-1153 for the transient guard.

## External trust and enforcement boundaries

- The `TransparentUpgradeableProxy` administrator can change implementation code and therefore sits above these application-level invariants. It is a separate deployment authority from the StateOracle owner and roles.
- Admin verifiers define who may express assignment intent for each adopter. StateOracle does not store a permanent adopter-admin key.
- DA verifiers define acceptable proof of deployment-payload availability. They do not certify trigger-manifest correctness.
- Manifest validators define schema validity and trigger-unit pricing for future installations. Governance replacement does not rewrite installed state.
- The assertion executor and indexers enforce effective blocks, successive generations, canonical log order, confirmations, replay behavior, and reorg handling. Those properties cannot be proven by the StateOracle contract alone.
- The platform owns the mapping between its project record and the random on-chain project ID. The contract does not know the platform UUID or enforce cross-oracle uniqueness.

## Project retirement proof

Retirement does not enumerate adopters or assertions. Instead, it requires `usedTriggerUnits == 0`. This is equivalent to no enabled installation only because all of the following remain true:

1. every enabled installation has `triggerUnits > 0`;
2. adopter counts and project usage are updated atomically with installation state; and
3. per-project trigger conservation holds.

Changes to validation or accounting must preserve this proof or replace the retirement condition with an equally strong one.

## Verification map

| Guarantee | Repository coverage |
| --- | --- |
| Exclusive assignments and ghost-state agreement | `invariant_assignmentsMatchGhostStateAndRemainExclusive` |
| Enabled installations require active assignment; adopter counts conserve | `invariant_enabledAssertionsRequireAnActiveAssignmentAndCountsConserve` |
| Per-project and global trigger-unit conservation | `invariant_projectAndGlobalTriggerUnitsConserve` plus admission/removal fuzz tests |
| Terminal retirement tombstones | `invariant_retirementIsATerminalZeroedTombstone` plus retirement edge/fuzz tests |
| Owner/default-admin coupling | `invariant_ownerAndDefaultAdminRemainCoupled` plus ownership and role-hierarchy unit tests |
| Role isolation, recovery, pause behavior, detach, and registration bounds | `StateOracleV2.t.sol` and `StateOracleV2FuzzAndCoverage.t.sol` |
| Per-key lifecycle/reset guard, batching rollback, and same-block re-add | `StateOracleV2ExecutorEventGuardTest` and `StateOracleV2InstalledAssertionTest` |
| Downstream ordering, replay, restart, confirmation, and reorg behavior | Cross-repository executor and indexer tests; not proven by this repository |

## Guidance for contract changes

When changing V2:

1. Update the role table and pause matrix if any authorization or modifier changes.
2. Update the struct section and downstream ABI artifacts if public storage getters, events, errors, or calldata structs change.
3. Preserve the owner/`DEFAULT_ADMIN_ROLE`, assignment, count, and trigger-conservation invariants.
4. Treat event order, effective-block semantics, and generation identity as an external API consumed by the assertion executor and platform indexers.
5. Add unit, fuzz, and stateful invariant coverage for behavior changes. The primary suites are:
   - `test/StateOracleV2.t.sol`
   - `test/StateOracleV2FuzzAndCoverage.t.sol`
   - `test/StateOracleV2.invariant.t.sol`
6. Keep V2 fresh-deployment assumptions explicit. Do not add an importer, migration role, or privileged accounting bypass without a separate design review.

## Sources

- [`StateOracleV2.sol`](../src/StateOracleV2.sol)
- [`StateOracleV2AccessControl.sol`](../src/StateOracleV2AccessControl.sol)
- [`StateOracleV2.t.sol`](../test/StateOracleV2.t.sol)
- [`StateOracleV2FuzzAndCoverage.t.sol`](../test/StateOracleV2FuzzAndCoverage.t.sol)
- [`StateOracleV2.invariant.t.sol`](../test/StateOracleV2.invariant.t.sol)
- [StateOracle V2 design and decisions](https://app.notion.com/p/3aa85d07a17b8157b224c2b911fba182)

## Recommended follow-up documentation

- A production operations runbook containing deployed role holders, multisig thresholds, key-rotation procedures, and exact pause, quarantine, recovery, and retirement transactions.
- A cross-repository event-consumer specification covering confirmation depth, reorg handling, canonical log ordering, idempotency keys, and successive assertion generations.
- A per-chain deployment manifest recording oracle, proxy admin, verifier, validator, timelock, and role addresses without mixing those mutable deployment facts into this architecture reference.
