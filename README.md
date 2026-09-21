# Split-Brain Fabric

**Split-Brain Fabric 1.0.0** is a C++20 runtime that answers one question
deterministically:

> Given competing control domains or coordinators claiming authority over
> overlapping fabric scope, **which authority is valid now, what must be fenced,
> and when must all sides remain non-authoritative until quorum, witness, or
> reconciliation evidence is sufficient?**

It owns split-brain prevention and authority fencing for fabric control domains.
It does **not** implement a general-purpose consensus system: it consumes
configured quorum/witness/lease evidence and decides whether a domain may act.

---

## 1. Product boundary

**In scope**

* deciding whether one control domain may mutate a fabric scope right now;
* binding every decision to domain, scope, epoch/term, process incarnation,
  witness/quorum evidence, lease, and a durable fencing token;
* fencing superseded, restarted, partitioned or replayed authority so that it can
  never act again;
* modelling overlapping scopes explicitly, and allowing non-overlapping domains
  to remain authoritative when policy permits;
* reconciling diverged durable histories by preserving lineage and surfacing
  conflicts instead of silently choosing one history;
* a durable, integrity-checked log and a fenced mutation target;
* an operator CLI, a framed control protocol and an offline auditor.

**Out of scope (and not claimed)**

* general consensus, leader election among arbitrary participants, or Paxos/Raft;
* authentication, encryption or any cryptographic security (see §11);
* physical fabric programming: switches, NICs, RDMA, SmartNICs, DPUs, NVLink,
  InfiniBand, RoCE and multi-node behaviour are **UNSUPPORTED** here;
* scheduling, orchestration, or the workloads that run on the fabric.

Adjacent runtime responsibilities are integrated only through explicit typed
inputs, evidence, references and authority boundaries.

---

## 2. Architecture

```
        +------------------+        framed TCP         +---------------------+
        |  sbf-coordinator | <----------------------> |    sbf-registry     |
        |  (control domain)|   allocate / decide /    |  durable authority  |
        |                  |   commit / fence         |  single serialiser  |
        +---------+--------+                          +----------+----------+
                  |                                              |
                  |  attest(domain, scope, epoch, incarnation,   |  fenced append
                  |         fence token)                         v
                  |                                   +---------------------+
        +---------v--------+  +-----------------+     |  fabric effect log  |
        |   sbf-witness    |  |   sbf-witness   |     | (durable token floor|
        |   (quorum vote)  |  |   (quorum vote) |     |  per extent)        |
        +------------------+  +-----------------+     +---------------------+
```

| Component | Role | Durable state |
|---|---|---|
| `sbf-registry` | owns every authority decision; single serialisation point | domain definitions, policy, fence table, epoch lineage, boot/incarnation counters, committed effects, interrupt marks |
| `sbf-witness` | one quorum vote; refuses conflicting attestations per (domain, scope, epoch) | nothing (a witness holds no durable authority) |
| `sbf-coordinator` | a control-domain coordinator; never self-authorises | nothing |
| `sbfctl` | operator tool and offline auditor | nothing |

Three independent enforcement layers, deliberately not sharing state:

1. **Evidence.** A witness refuses to attest two different incarnations for the
   same (domain, scope, epoch). A partitioned side therefore cannot assemble a
   quorum, and an epoch can only advance through the registry.
2. **Durable fence registry.** The registry fences every overlapping open grant
   before opening a new one, and never reissues a fence token. Tokens are
   strictly increasing and are never reused.
3. **Effect boundary.** The fenced fabric log refuses any mutation whose token is
   below the durable high-water mark for any extent in scope, or whose
   incarnation is not the recorded owner. This layer does not consult live
   authority state at all, so a coordinator that believes — wrongly — that it
   still holds authority cannot mutate the fabric.

### Library layout

| Area | Header |
|---|---|
| Typed identities, counters, wall-clock observation | `sbf/ids.hpp`, `sbf/limits.hpp`, `sbf/clock.hpp` |
| Outcomes and reason codes | `sbf/status.hpp` |
| Deterministic encoding, CRC-32C, SHA-256 | `sbf/canonical.hpp`, `sbf/digest.hpp` |
| Scope algebra and bounded overlap index | `sbf/scope.hpp` |
| Evidence model and quorum assessment | `sbf/evidence.hpp` |
| Authority vectors, verdicts, decisions | `sbf/authority.hpp` |
| Fence table | `sbf/fence.hpp` |
| Epoch lineage, boot registry, reconciliation | `sbf/lineage.hpp` |
| Deterministic decision function and planner | `sbf/arbiter.hpp` |
| Durable log | `sbf/persistence.hpp` |
| Fenced effect boundary | `sbf/fabric_store.hpp` |
| Framed protocol and codecs | `sbf/protocol.hpp` |
| Services and clients | `sbf/registry.hpp`, `sbf/witness.hpp`, `sbf/coordinator.hpp` |
| Invariant auditor | `sbf/audit.hpp` |

---

## 3. Authority model

A decision is legal only when **all** of the following are bound and agree:

| Binding | Type | Meaning |
|---|---|---|
| domain | `DomainId` | which control domain claims authority |
| scope | `Scope` | exact extent set (canonical, sorted, unique) |
| epoch / term | `Epoch` | monotone per domain; a superseded epoch never returns |
| incarnation | `IncarnationId` | process boot identity, issued durably by the registry |
| witness evidence | `QuorumProfile` + `WitnessAttestation[]` | distinct witnesses, generations, sequences |
| lease | `Lease` | epoch- and incarnation-bound validity window in logical steps |
| fence token | `FenceToken` | durable, strictly increasing, never reused |
| generations | `Generation` | policy, evidence, fence-table generations |
| attempt | `Sequence` | monotone per authority; makes allocation idempotent |

Every externally visible decision:

* identifies the exact subject and scope it applies to;
* binds the generations/evidence that made it legal;
* distinguishes positive authority from observation, eligibility,
  recommendation, acknowledgement and verified effect;
* carries deterministic reason codes;
* exposes `UNKNOWN`, `STALE`, `CONFLICT`, `INVALID` and `UNSUPPORTED`
  explicitly;
* is revocable through `check_revocation`, which fires whenever any
  authority-bearing dependency changes.

### Verdict vocabulary

`AUTHORITATIVE`, `FENCED`, `OBSERVE_ONLY`, `ELIGIBLE`, `RECOMMENDED`,
`ACKNOWLEDGED`, `APPLIED`, `UNKNOWN`, `STALE`, `CONFLICT`, `INVALID`,
`UNSUPPORTED`, `REFUSED`, `INTERRUPTED`.

Exactly one verdict — `AUTHORITATIVE` — permits a mutation
(`verdict_permits_mutation`). In particular `APPLIED`, which reports an effect
that already happened, does not.

### Things that are never authority

* matching identifiers without matching generations;
* a durable record without current evidence;
* an observation, an eligibility probe, advice, or an acknowledgement;
* a reply that has not been verified as an effect;
* wall-clock recency of any kind.

---

## 4. Invariants

1. **MUTEX.** For a given exclusive extent, at most one authority vector is
   authoritative at a time. Two incarnations claiming the same epoch for
   overlapping extents is a conflict in which *both* sides stay
   non-authoritative.
2. **MONOTONE EPOCH.** Epochs per domain are strictly increasing. A superseded
   epoch is refused by the registry, by the witnesses and by the effect
   boundary.
3. **MONOTONE FENCE.** Fence tokens are strictly increasing, globally unique, and
   never reused. Once an extent's high-water mark rises, every lower token is
   permanently refused for that extent.
4. **NO RESURRECTION.** A fenced incarnation can never return, through restart,
   replay, reconnection or duplicate message.
5. **FAIL CLOSED.** When authority cannot be proven the answer is `UNKNOWN`,
   `STALE`, `CONFLICT`, `INVALID` or `UNSUPPORTED` — never a mutation.
6. **PERSISTENCE IS NOT LIVENESS.** Restoring a record never restores freshness,
   lease validity, or process authority.
7. **LINEAGE PRESERVED.** Reconciliation returns the union of both histories and
   lists every conflict; it never picks a winner.
8. **BOUNDED.** Every table, history, queue, frame, document, explanation and
   retained attempt is bounded, and exceeding a bound is a deterministic refusal.

---

## 5. Lifecycle and restart semantics

**Persisted (durable definitions, lineage and outcomes):**

* store identity and format version, logical step floor;
* domain definitions and policy;
* the fence table (per-extent high-water marks, fence records, fenced
  incarnations and epochs);
* the epoch lineage (grants, boots) and interruption marks;
* committed fabric effects and the per-extent durable token floor;
* the incarnation counter, journalled before an incarnation is handed out.

**Never persisted (dynamic liveness):** leases, attestations, evidence bundles,
session bindings, in-flight attempts and open sockets. A restart cannot convert
any of them into current authority.

**On restart the registry:**

1. opens the durable log and the fenced fabric log, rejecting corrupt headers,
   unsupported versions, impossible lengths, invalid enums, sequence regression
   and trailing garbage;
2. recovers only a genuinely truncated final record, and reports it;
3. raises its own token counter above every durable high-water mark — including
   the effect boundary's, which dominates;
4. closes every previously open grant as `INTERRUPTED` and fences its
   incarnation and epoch, emitting a durable interrupt mark;
5. ends the previous boot as interrupted and opens a new boot with a strictly
   greater incarnation.

A grant that was open when the process died is therefore never resumed: it is
fenced, marked, and visible to the offline auditor.

---

## 6. Build, install and use

Requires CMake 3.20+, a C++20 compiler, and no third-party runtime dependency.
On Windows the library links `ws2_32`; elsewhere it uses POSIX sockets and
pthreads.

```
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
cmake --install build --prefix /some/prefix
```

Options: `SBF_BUILD_TOOLS`, `SBF_BUILD_EXAMPLES`, `SBF_BUILD_TESTS`,
`SBF_WARNINGS_AS_ERRORS`, `SBF_ENABLE_SANITIZERS` (non-MSVC), `SBF_ENABLE_IPO`.

### Downstream consumer

```cmake
find_package(SplitBrainFabric 1.0 CONFIG REQUIRED)
target_link_libraries(my-app PRIVATE SplitBrainFabric::sbf)
```

`tests/install_consumer/` is a self-contained project that consumes only the
installed package; the `sbf-test-install-consumer` ctest entry installs the
project into a scratch prefix, configures that project against it, builds, links
and runs it.

*Note:* on Windows, run the consumer test from a developer (vcvars) environment,
or let the generated test forward the compiler path, as the default ctest entry
does.

---

## 7. Framed protocol

One bounded, framed message stream. Header is 32 bytes:

| offset | size | field |
|---|---|---|
| 0 | 4 | magic `0x31464253` ("SBF1" little-endian) |
| 4 | 2 | protocol version (1) |
| 6 | 2 | message type |
| 8 | 4 | flags |
| 12 | 8 | request id |
| 20 | 4 | payload length |
| 24 | 4 | header CRC-32C over bytes [0,24) |
| 28 | 4 | payload CRC-32C |

Properties:

* the declared payload length is validated against the configured maximum
  **before** any allocation;
* decoding is total: every malformed input maps to a specific reason;
* a decoder that has seen a malformed frame refuses all further frames (sticky
  failure) and the connection is closed without a reply;
* every enum, domain and range is validated; truncated prefixes, corrupt frames,
  trailing bytes and oversized declarations are rejected;
* a session is established by a handshake in which the **server** assigns the
  session id and incarnation. A request whose declared identity differs from its
  session binding is rejected and the connection is closed. Request ids must
  strictly increase within a session.

---

## 8. Tools

```
sbf-registry --dir <store-dir> --store <id> --node <id> --port 0 \
             --quorum threshold:2 --witness w0:rack-a@127.0.0.1:9100 \
             --witness w1:rack-b@127.0.0.1:9101 \
             --define domain-a:coordinator-a:fabric-policy:port-1,port-2 \
             --announce <file>

sbf-witness --id witness-0 --fault-domain rack-a --port 0 --announce <file>

sbf-coordinator --node coordinator-a --domain domain-a --scope port-1,port-2 \
                --registry 127.0.0.1:9000 --witness-target witness-0:rack-a@127.0.0.1:9100 \
                --ops 100 --operation switch-port

sbfctl version | inspect | define | witness-status | shutdown | audit | plan
```

`sbfctl audit --dir <store-dir> --store <id>` is an **offline** verifier: it
reopens the durable store without a live registry, replays it, and reports the
registry and effect-history audits, exiting non-zero if either finds a violation.
It is what the multiprocess proofs use to check the converged on-disk state.

---

## 9. Examples

`examples/fence_cycle.cpp` (built as `sbf-example-fence`) runs a complete
authority cycle against loopback services: define a domain, acquire an epoch and
a durable fence token, collect quorum evidence, mutate through the fenced effect
boundary, then hand over to a successor and audit the result. It prints
`EXAMPLE OK` and exits zero when the effect history is mutually exclusive.

---

## 10. Test and proof suite

`ctest` runs eleven suites. There is no timeout anywhere: a hanging test is a
defect to diagnose, not something to hide behind a watchdog.

| Suite | What it proves |
|---|---|
| `sbf-test-unit-core` | identifiers, checked arithmetic, canonical encoding bounds, SHA-256/CRC-32C known answers, scope algebra with a differential test against an independent reference, fence and lineage monotonicity, reconciliation lineage preservation |
| `sbf-test-codec-protocol` | frame round trips, every truncated prefix, oversized declared lengths refused before allocation, sticky failure, arbitrary chunk boundaries, all message codecs, decision-digest binding, malformed encodings |
| `sbf-test-unit-arbiter` | quorum sufficiency, duplicate/replayed witness messages, conflicting attestations, stale epochs, incarnation fencing, equal-epoch conflict, higher-epoch claimants, non-overlapping authority, revocation, and a wall-clock-invariance property test |
| `sbf-test-unit-selection` | the planner against an independently written exhaustive reference over thousands of seeded instances, order independence, adversarial instances that defeat a greedy heuristic, explicit `SEARCH_LIMIT_REACHED` |
| `sbf-test-persistence` | reopen, checkpoint, torn-tail recovery, complete-but-corrupt records never truncated, impossible lengths, sequence gaps, unknown kinds, trailing garbage, snapshot integrity, atomic replacement |
| `sbf-test-integration` | full authority cycle over loopback, two coordinators over one scope, non-overlapping domains, partition, client-kind gate, scope registry, release fencing, session limit |
| `sbf-test-adversarial` | replayed leases, expired leases below a full quorum, witness replay floors, clock skew and backwards clocks, delayed completions after succession, restart at every boundary, corrupt snapshot refusal, torn tail |
| `sbf-test-concurrency` | prompt shutdown with blocked accepts and blocked reads, concurrent clients serialised without loss or epoch regression, witness shutdown, repeated open/close cycles, double stop/join |
| `sbf-test-scale` | planner node counts across scales, overlap computation cost ratio, durable append cost, bounded retained state, witness subject-table exhaustion |
| `sbf-test-multiprocess` | **real processes, real loopback sockets**: competition, hard kill and controlled succession, partition, registry hard kill and restart |
| `sbf-test-install-consumer` | install, `find_package` from the installed prefix, build, link, run |

Property suites print their deterministic seed and accept `--seed` and
`--filter=` for exact reproduction.

---

## 11. Trust boundary and security statement

* **No authentication and no encryption.** CRC-32C and SHA-256 provide integrity
  and content identity only; nothing is keyed. The trust boundary is a local,
  mutually-trusting control plane (loopback).
* Session binding establishes *identity binding*, not authenticity: a request can
  never act under another session's identity, boot or epoch, but the transport
  does not prove who sent it.
* Witness attestations are integrity-checked and structurally validated, not
  authenticated. The safety property does not rest on attestation authenticity
  alone: the registry's durable fence registry and the effect boundary's token
  floor are independent backstops, and both are process-local durability
  guarantees.
* Durable records are flushed with `fflush` + `fsync`/`_commit`, which
  places them in the operating system's durable-storage path. This is not a
  media-level verification.
* Operators who need authenticated or encrypted transport must place this runtime
  behind a mutually authenticated channel; that is deliberately outside the
  boundary. A pluggable authenticator is an extension point, not an implemented
  feature.

---

## 12. Evidence matrix

| Claim | Status |
|---|---|
| Two real coordinator processes competing for one overlapping exclusive scope; at most one commits | **REAL** — `sbf-test-multiprocess`, real OS processes, real loopback sockets |
| Hard kill of the authoritative coordinator and controlled successor acquisition behind a durable fence | **REAL** — `TerminateProcess`/`SIGKILL` mid-run, then successor acquisition and an offline audit |
| Network-partition simulation where each side sees itself but lacks witness evidence | **REAL as endpoint isolation** — witness processes are killed, so the isolated coordinator genuinely cannot reach them. Not a physical link partition. |
| Replayed leases, stale epochs, clock skew, backwards clocks, duplicate witness messages, delayed completions | **SYNTHETIC** — deterministic constructed evidence, labelled in the test source |
| Property invariant: never two simultaneous authoritative owners for the same exclusive scope | **REAL** (in-process property tests over thousands of seeded instances) **and REAL** (multiprocess effect-history audit) |
| Restart and reopen proof | **REAL** — real process termination and reopen of the durable store, plus real registry hard kill and restart |
| Framed protocol behaviour | **REAL** — real sockets, real byte streams |
| Scale and benchmark | **REAL** measurements on this host; absolute numbers are host-specific |
| AddressSanitizer/UBSan | see §13 — recorded per host |
| Static analysis | see §13 — recorded per host |
| Physical switch/NIC/RDMA/SmartNIC/DPU/NVLink/InfiniBand/RoCE/multi-node behaviour | **UNSUPPORTED** — never exercised, never claimed. Scope extents are opaque labels supplied by configuration. |
| General consensus (Paxos/Raft) | **UNSUPPORTED** — deliberately out of scope |

---

## 13. Build and validation matrix on this host

| Configuration | Result |
|---|---|
| Release, x64, `/W4 /WX /permissive-` | built; 11/11 ctest suites pass |
| Debug, x64, `/W4 /WX /permissive-` | built; 11/11 ctest suites pass |
| MSVC static analysis, x64, `/analyze /wd6101` over all 25 library translation units | **0 warnings, 0 errors** |
| AddressSanitizer, **x86 (32-bit)** target, `/fsanitize=address` | built; 11/11 ctest suites pass, no ASan findings |
| AddressSanitizer, x64 | **UNSUPPORTED on this host**: the x64 ASan runtime is not installed. The exact missing components are `clang_rt.asan_dynamic-x86_64.lib`, `clang_rt.asan_dynamic_runtime_thunk-x86_64.lib` and `clang_rt.asan_static_runtime_thunk-x86_64.lib` under `VC\Tools\MSVC\<ver>\lib\x64` (the i386 equivalents are present). Install the "C++ AddressSanitizer" component to enable it. |
| UndefinedBehaviorSanitizer | **UNSUPPORTED on this host**: MSVC has no UBSan; it is available only through clang/gcc, neither of which is installed here. |
| Install + independent downstream consumer | pass (`sbf-test-install-consumer`) |
| Installed-artifact end-to-end run | pass (`scripts/installed-artifacts-check.ps1`) |
| Fresh-clone closure | pass (`scripts/fresh-clone-check.ps1`) |

Sanitizer coverage is therefore **partial and labelled**: the algorithmic,
persistence, protocol, service, concurrency and multiprocess suites were all run
under a real AddressSanitizer build, but that build was 32-bit because the 64-bit
ASan runtime is absent from this machine. 64-bit sanitizer coverage is not
claimed.

---

## 14. Genuine limitations

* **No physical hardware validation.** Nothing in this release has been run
  against a real switch, NIC, RDMA/RoCE link, DPU, SmartNIC or multi-node
  cluster. Scope extents are configuration labels, and the effect log is a local
  file. All such claims are UNSUPPORTED.
* **No authentication or encryption.** See §11.
* **Single registry.** The registry is a single serialisation point and a single
  point of availability. Safety does not depend on its availability — when it is
  unreachable, coordinators fail closed and mutate nothing — but availability
  does. Registry replication is out of scope.
* **Bounded history.** The lineage and fence-record tables are bounded; the
  oldest *audit* records are dropped when full. Enforcement lives in the monotone
  high-water marks, which are never dropped, so dropping history cannot resurrect
  authority.
* **Incarnation ids are bounded.** They are issued from a durable counter; the
  counter refuses to wrap rather than reuse an id.
* **Shutdown latency.** Service worker threads observe a stop request between
  bounded readability waits, so shutdown is prompt (tens of milliseconds) rather
  than instantaneous. No correctness property depends on that duration; it was
  introduced because shutting a socket down does not reliably interrupt a blocked
  `recv` on every supported platform.
* **Durability is OS-level.** Records are flushed to the operating system's
  durable path, not verified at the media level.
* **Sanitizer coverage is 32-bit only on this host.** AddressSanitizer was
  available for the x86 target only, because the x64 ASan runtime is not
  installed; see §13. UndefinedBehaviorSanitizer and clang/gcc builds were not
  available at all.
* **No 32-bit production claim.** The 32-bit build exists solely as the sanitizer
  vehicle. The supported target is x64.
* **Wall clock is diagnostic only.** Wall-clock readings are recorded and
  regressions are counted, and a property test asserts that perturbing them never
  changes a decision — but they are not, and never become, an ordering input.

---

## 15. Repository layout

```
include/sbf/      public headers
src/              library implementation
tools/            sbfctl, sbf-registry, sbf-witness, sbf-coordinator
examples/         fence_cycle example
tests/            eleven ctest suites + install consumer project
scripts/          installed-artifacts-check.ps1, fresh-clone-check.ps1
docs/             ownership audit and concurrency analysis
cmake/            package config and version templates
```

## License
Apache License 2.0. Copyright 2026 Summon Software Labs.
