# Review: Async HTTP Refactor (92882c4..f364d97)

Review of the Changes entry:
> Provide an EXPERIMENTAL mechanism for asynchronous HTTP. This involved
> a significant refactor of the internals, which may affect synchronous
> operation.

## Summary

The refactor introduces a dual-mode (sync/async) architecture by:

1. **PromiseUtil.pm** — A shim that dispatches between promise chains and
   plain values. `then()` calls `->then()` on promises, or invokes the
   callback directly for non-promise values. `do_then_catch()` provides
   try/then/catch semantics for both modes.

2. **Every public I/O method** in ACME2.pm now returns through
   `PromiseUtil::then()`, making them transparently promise-aware.

3. **HTTP.pm** refactored to accept a custom UA (async) or default to
   HTTP_Tiny (sync). Error handling moved from eval/die to `do_then_catch`.

4. **HTTP::Convert.pm** — Error transformation logic extracted from HTTP_Tiny,
   now shared between sync and async paths.

5. **Curl.pm** — New async backend wrapping Net::Curl::Promiser.

The approach is clean: sync callers see no behavioral change (plain values
flow through PromiseUtil as pass-through), while async callers get real
promise chains.

**All 284 tests pass.**

---

## Findings

### Medium — badNonce retry counter is no longer stack-safe

**File**: `lib/Net/ACME2/HTTP.pm:184`

Old code used `local $self->{'_retries_left'}` which auto-restored on
stack unwind. New code permanently decrements with `$self->{'_retries_left'}--`.

This works because both the success path (line 164) and the non-badNonce
error path (line 195) reset to `$_MAX_RETRIES`. But if an unrelated
exception occurs between the decrement and the reset, retries won't
restore. Practical risk is low since the reset paths are comprehensive,
but it's a behavioral change worth noting.

**Suggestion**: Add a comment explaining why `local` was replaced
(incompatible with promise chains) and that the explicit resets are
intentional.

### Medium — `_sync_io` flag is dead code

**File**: `lib/Net/ACME2/HTTP.pm:56`

`$is_sync` is computed and stored as `_sync_io` but never referenced
anywhere in the codebase. Either this is planned infrastructure for
future sync-path optimizations, or it should be removed.

### Medium — Curl.pm header parsing doesn't guard against empty lines

**File**: `lib/Net/ACME2/Curl.pm:138-163`

`_imitate_http_tiny` splits on `\x0d?\x0a` which can produce empty
strings (e.g., the blank line separating headers from body, or trailing
CRLF). When an empty line hits `split m<\s*:\s*>, $line, 2`, it produces
a single-element list with `$name = ""` and `$value = undef`. This adds
an `undef` value to `%headers` under the empty-string key.

This doesn't crash because HTTP::Convert doesn't inspect arbitrary
header keys, but it's unclean. A `next if !length $line` guard after
the split would fix it.

### Medium — Commented-out code left in

**Files**:
- `lib/Net/ACME2/HTTP.pm:147` — `# local $opts_hr->{'headers'}...`
- `lib/Net/ACME2.pm:1186-1188` — Commented-out DESTROY sub

These are debug/development artifacts that should be cleaned up before
release.

### Low — `_directory_promise` naming is misleading in sync mode

**File**: `lib/Net/ACME2.pm:1046`

In sync mode, `_directory_promise` caches a plain hash reference (the
directory struct), not a promise. The name could mislead future
maintainers. Consider `_directory_cache` or just `_directory`.

### Low — HTTP_Tiny.pm no longer preserves `$@` independently

**File**: `lib/Net/ACME2/HTTP_Tiny.pm:88-97`

The old code explicitly saved/restored `$@` around HTTP::Tiny calls
because HTTP::Tiny clobbers it. This protection was removed, making
HTTP_Tiny.pm reliant on HTTP.pm's `do_then_catch` to handle `$@`.

This is fine for the normal call path, but means HTTP_Tiny.pm is no
longer safe to use independently. Since it's an internal module, this
is acceptable but worth documenting.

### Low — Curl.pm redundant `shift()` in then callback

**File**: `lib/Net/ACME2/Curl.pm:104-108`

```perl
my ($easy) = @_;
return _imitate_http_tiny( shift(), @{$easy}{'_head', '_body'} );
```

`$easy` and `shift()` refer to the same value. Harmless but confusing.

### Low — No `$verify_SSL` equivalent for Curl backend

**File**: `lib/Net/ACME2/Curl.pm`

HTTP_Tiny respects `$Net::ACME2::HTTP::verify_SSL` for testing. Curl
has no equivalent. Curl defaults to SSL verification (safe), but there's
no test-time override. Users can work around this via `set_easy_callback`,
but it's an asymmetry.

### Low — Version regex bugfix (positive finding)

**File**: `lib/Net/ACME2/HTTP_Tiny.pm:55`

Old: `s<[^0-9].].*><>` — the `]` was unescaped inside the character
class, matching literal `]`. New: `s<[^0-9.].*><>` — correct. This is
a quiet bugfix.

---

## Architectural Assessment

The dual-mode approach via PromiseUtil is elegant and minimally invasive.
The key insight — that `then(non_promise, callback)` can just call the
callback synchronously — means the sync path has near-zero overhead
despite all the promise plumbing.

The `do_then_catch` function properly preserves `$@`, which was the
trickiest part of the old eval/die error handling. The extraction of
`_xform_http_error` as a standalone method is a clean separation.

The changelog warning about "may affect synchronous operation" is
warranted and honest. The behavioral changes are:

1. **Return values**: Methods now technically return through callback
   chains rather than directly. In sync mode, the values are identical,
   but the execution path is different (function calls through closures).

2. **`$@` preservation**: Now handled at the `do_then_catch` level rather
   than scattered through individual methods. More centralized, arguably
   better.

3. **badNonce retry**: Mutation-based instead of local-based. Functionally
   equivalent for normal flows.

None of these changes should affect production sync users, but the test
suite should be expanded to cover error paths more explicitly — currently
only `t/Net-ACME2-HTTP.t` exercises the HTTP layer, and it doesn't test
badNonce retry or `$@` preservation.
