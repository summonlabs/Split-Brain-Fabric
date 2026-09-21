# Ownership and concurrency audit

This document records the deliberate ownership/lifecycle inspection required
before closure, the defects it found, and how each was fixed. It is a working
audit, not a claim of exhaustiveness.

## 1. Ownership model

| Object | Owner | Notes |
|---|---|---|
| `RegistryState` | `RegistryService` | mutable only while `state_mutex_` is held, on any connection thread |
| `Store` / `FabricStore` | `RegistryService` / `RegistryState` | move-only; the file handle is transferred and nulled in the source |
| `net::Socket` | one `shared_ptr` per connection, shared with `ConnectionHub` | move-only; the handle is nulled on move so a moved-from socket cannot double-close |
| `net::Listener` | the service | `stop()` is idempotent |
| connection worker thread | detached, self-deregistering through `ConnectionHub` | the service waits for the active count to reach zero before `join()` returns |
| `FrameDecoder` | its connection worker | poisoned decoders never recover without an explicit `reset()` |

## 2. Threading contract

* One thread per accepted connection, owning its socket and frame decoder.
* A single `state_mutex_` guards every service-state transition.
* The lock is **never** held across a socket write and **never** held across a
  callback, log sink or response encoder. The pattern is: lock, transition
  (including the durable journal append that belongs to that transition), copy
  the response bytes into a local string, unlock, then write.
* Every worker takes at most one service lock at a time, and never while
  performing socket I/O. There is no second service-level mutex, so cross-object
  mutex order inversion is structurally impossible between registry and witness
  state.
* Shutdown order: set the stop flag -> stop the listener (which wakes a blocked
  `accept`) -> shut every live socket down -> wait on a condition variable for
  the active count to reach zero -> join the accept thread.

### Checklist walked explicitly

| Hazard | Finding |
|---|---|
| read-lock then write-lock re-entry on the same lock | none: `state_mutex_` is a plain `std::mutex` taken exactly once per request; no recursive acquisition exists |
| write lock held across helper/callback paths that re-enter state | none: `append_records` is called with the lock held but touches only the store; no visitor re-enters `RegistryState` |
| event/log/callback invocation beneath internal locks | none: no callbacks are invoked under any lock; responses are encoded into locals |
| joining workers while holding state they need | none: `join()` is called with no service lock held; workers take the state lock only inside `release_session` |
| cancellation/shutdown with reversed lock ordering | none: `ConnectionHub` uses its own mutex and never calls into service state; the service lock is never taken while holding the hub mutex |
| blocked socket/thread teardown | **defect found and fixed**, see D6/D7 |
| cross-object mutex order inversion | none: hub mutex and state mutex are never held simultaneously |
| moved-from handle ownership | **defect found and fixed**, see D3 and D4 |
| close/shutdown races and double-close | `Socket` and `Store` null their handles on move; `close()` and `stop()` are idempotent |
| callbacks retaining references to mutable state beyond lock lifetime | none: no callback outlives its call |

## 3. Defects found and fixed during hardening

Each entry lists the defect, how it was found, and the fix.

### D1 — Planner indexed the conflict matrix with preference ranks

`select_authority_set` stored *preference ranks* in its partial selection but
indexed `legal[]`/`conflict[][]` (which are indexed by *candidate*) with those
ranks. When the input order happened to coincide with the preference order the
two were identical and the solver was correct; for any other input it read the
wrong pairs and silently returned a smaller-than-optimal set.

*Found by:* the order-independence property test
(`selection.plan_is_independent_of_candidate_order`) — 636 failing cases.

*Fixed:* selections are now carried as candidate indices; ranks are used only
for the canonical tie-break comparison.

### D2 — Store header CRC was verified at the wrong offset

`decode_store_header` computed the CRC field offset as
`bytes.size() - (remaining + 4)` instead of `bytes.size() - remaining`, so the
CRC was compared against a window shifted by four bytes and every reopen of an
existing store failed with `Corrupt:IntegrityMismatch`.

*Found by:* `persistence.append_reopen_and_sequence_continuity`.

*Fixed:* the CRC position is captured before the field is consumed.

### D3 — `Store` leaked its journal handle

`Store` had no destructor closing its `FILE*`, so every store kept its journal
handle for the lifetime of the process.

*Found by:* the ownership audit.

*Fixed:* an explicit destructor closes the handle.

### D4 — `Store` move left a dangling handle

The first fix for D3 made `Store` close its handle in the destructor while the
defaulted move constructor copied the pointer, so the moved-from temporary in
`Store::open` closed the very handle the destination was using. Every append
then failed with `Unreachable:EffectNotVerified`.

*Found by:* `persistence.append_reopen_and_sequence_continuity` (immediately
after D3 was fixed).

*Fixed:* explicit move construction/assignment that transfer the handle and null
it in the source, matching `FabricStore` and `net::Socket`.

### D5 — A witness re-issuing at a higher sequence was rejected

`assess_evidence` recorded only the *first* sequence it saw from a witness and
rejected every later one as "not newer", so a legitimate refresh was discarded
and duplicate/replay counters never incremented.

*Found by:* `arbiter.duplicate_witness_messages_never_inflate_the_quorum`.

*Fixed:* assessment first reduces the bundle to the highest-sequence statement
per witness and counts every other occurrence as a duplicate/replay. The result
is a function of the statement *set*, which is also what makes the assessment
order-independent.

### D6 — Registry handshake failures were reported as success

`handle_hello` returned a failing `Status` while leaving
`HelloResponse::status` at its default `Ok`, so a refused handshake looked like
a successful one to the client. Consequently the session limit was never
enforced and clients silently connected to a server that had rejected them.

*Found by:* `integration.max_sessions_is_enforced_without_instability`.

*Fixed:* the worker sets `response.status` from the handler result and closes
the connection.

### D7 — Shutdown/accept race left a connection registered after the stop snapshot

`ConnectionHub::begin_stop` snapshotted the live sockets and then shut them
down. A connection accepted *between* the snapshot and the shutdown was
registered afterwards and never shut down, so its worker parked forever in a
blocking read and `wait_drained` never returned. The registry hung on shutdown.

*Found by:* `lifecycle.registry_shutdown_is_prompt_and_releases_blocked_accepts`.

*Fixed:* `ConnectionHub::add` performs the registration and the stopping check
under one lock; a connection that arrives after `begin_stop` is shut down
immediately. Either the socket is in the snapshot or it observes the flag, so
the race is closed rather than narrowed.

### D8 — Blocked `recv` was not interrupted by `shutdown` on this host

With D7 fixed, a direct experiment (a standalone Winsock program, kept out of the
repository) showed that `shutdown(socket, SD_BOTH)` from another thread does
**not** wake a blocked `recv` on this host, contrary to the documented
behaviour. Relying on it made worker teardown unreliable.

*Found by:* `lifecycle.registry_shutdown_is_prompt_and_releases_blocked_accepts`.

*Fixed:* worker threads wait for readability with `select` in bounded
increments and observe the stop flag between them; the socket is still shut down
so the wait returns promptly. Correctness never depends on the wait duration —
only shutdown latency does, and it is bounded by the increment.

### D9 — A coordinator's own re-acquisition fenced its own incarnation

`allocate_epoch` fences every overlapping open grant before opening a new one.
When the same live process asked again — a normal refresh — the previous grant
belonged to the *same* incarnation, and fencing it recorded that incarnation as
fenced, permanently disqualifying the process that had just asked. Every
concurrent allocation loop failed after the first round with
`Fenced:IncarnationFenced`.

*Found by:* `lifecycle.many_concurrent_clients_are_serialised_without_loss`.

*Fixed:* `fence_scope` takes an explicit `fence_incarnation` flag. Superseding
a different incarnation fences it; superseding the caller's own previous epoch
fences only the epoch and leaves the live incarnation current.

### D10 — Refusal decisions could not be transported

`RegistryState::decide` produced refusals that named no claim and sometimes no
domain. The `AuthorityDecision` codec rejected an empty claim id, so encoding a
refusal succeeded but decoding it failed. Coordinators saw a transport error
instead of the refusal, and reported `UNKNOWN` where the registry had said
`STALE`. Refusals — the most safety-critical messages in the system — were the
ones most likely to be misread.

*Found by:* `multiprocess.two_real_coordinators_compete_for_one_exclusive_scope`.

*Fixed:* the codec round-trips a decision that names no claim or domain (a
refusal before a subject is established is a legitimate, transportable outcome),
and the registry fills in the domain, scope, epoch, incarnation and fence token
it refused so the refusal identifies its subject.

### D11 — `sbf-registry` never set its policy identity

The CLI set the quorum profile's policy id but not `ArbiterPolicy::policy`, so
the registry refused to open with `Invalid:PolicyNotRegistered`.

*Found by:* `multiprocess.two_real_coordinators_compete_for_one_exclusive_scope`
(the tool could not start at all).

*Fixed:* the policy identity is taken from the quorum profile.

### D12 — Domain definition codec field order did not match the encoder

`decode_domain` read the policy id before the scope blob while `encode_domain`
wrote them in the opposite order, so every domain definition failed to decode
with `Corrupt:IdCharset`.

*Found by:* the example program, and then by every service test.

*Fixed:* the decoder follows the encoder exactly; both sites were corrected.

### D13 — Registry ignored shutdown requests
`RegistryService` answered a `ShutdownRequest` with a `ShutdownResponse` and then
kept running: the worker never set the stop flag or stopped the listener, so the
accept loop stayed parked and the process could only be killed externally.

*Found by:* `scripts/installed-artifacts-check.ps1`, which performs a controlled
shutdown of an installed registry and waits for its exit code.

*Fixed:* the worker sets the stop flag and stops the listener after the reply is
on the wire, so the client always learns the request was accepted and the run
thread then drains and exits. A regression test
(`integration.shutdown_request_stops_the_service`) covers it.

### D14 — `AuthorityDecision` did not record its subject scope

`decide_authority` never populated `AuthorityDecision::scope`, so decisions
carried an empty scope and failed to decode.

*Found by:* the example program.

*Fixed:* the decision records the exact scope it applies to, and the scope codec
distinguishes "no scope" (legal in a refusal) from a malformed scope.

### D15 — Test read through a dangling view
Two canonical-decoding checks constructed a `CanonicalReader` over a temporary
`std::string`. The reader stores a `std::string_view`, so it read freed memory.
Release builds happened to see the old bytes; the Debug build saw MSVC's 0xDD
freed-memory fill and failed.

*Found by:* the Debug configuration.

*Fixed:* the backing buffers are named locals that outlive the reader. A sweep of
every `CanonicalReader` construction confirmed the library sites all bind to
named buffers.

### D16 — 32-bit truncation warnings in snapshot handling
The sanitizer target exposed `C4244` conversions from `std::uint64_t` to
`std::size_t` when building a string view over a snapshot payload. Both are now
explicit, and the copy is length-checked immediately above.

*Found by:* the 32-bit build.

## 4. Residual risks

* The registry is a single process; `state_mutex_` is deliberately coarse. It
  serialises all authority transitions, which is exactly what makes mutual
  exclusion provable, but it is also the throughput ceiling of the control path.
  Durability (`fsync` per append) dominates measured latency anyway.
* Detached connection threads are tracked by count, not by handle; the service
  cannot attribute a stuck worker to a session beyond the hub snapshot. The
  bounded readability wait removes the blocking-forever failure mode this would
  otherwise hide.
* Witness state is per process and deliberately non-durable, so a restarted
  witness forgets what it attested. That is safe — a forgotten attestation can
  only make a quorum harder to reach — but it does mean witness restart reduces
  availability.
