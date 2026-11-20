# command
- mutmut run "*ǁ_get_future_callback__mutmut_*" --max-children 1

# `_get_future_callback()` Mutation Testing Summary

## 1. Objective

Evaluate whether the newly added concurrent DNS query tests improve fault detection in Future creation and callback association.

## 2. Mutation Target

- File: `aiodns/__init__.py`
- Function: `DNSResolver._get_future_callback()`
- Mutation tool: Mutmut 3.8.1
- Total mutants: 13

The function creates an `asyncio.Future` and associates it with a callback. Depending on the resolver configuration, callbacks are either scheduled through `loop.call_soon_threadsafe()` or invoked directly.

## 3. Test Suite Comparison

**Baseline:** Original aiodns test suite, excluding the newly added concurrent tests.

**Enhanced:** Original aiodns test suite, including the three concurrent tests:

- `test_concurrent_queries_out_of_order`
- `test_concurrent_queries_mixed_results`
- `test_concurrent_queries_mixed_types`

### Mutation Results

| Result | Baseline | Enhanced |
|---|---:|---:|
| Total Mutants | 13 | 13 |
| Killed | 6 | 6 |
| Survived | 0 | 0 |
| Timeout | 7 | 7 |
| Confirmed Kill Rate | 46.15% | 46.15% |

The Enhanced test suite produced the same mutation results as the Baseline.

## 4. Timeout Mutant Analysis

Seven mutants resulted in timeouts under both test suites.

| Mutant | Mutation Description |
|---|---|
| M04 | Replaced `self._callback` with `None` in the event-thread path |
| M05 | Replaced the bound Future with `None` in the event-thread path |
| M06 | Removed `loop.call_soon_threadsafe` from callback construction |
| M07 | Removed `self._callback` from the scheduled callback arguments |
| M08 | Removed the bound Future argument in the event-thread path |
| M11 | Replaced the bound Future with `None` in the non-event-thread path |
| M13 | Removed the bound Future argument in the non-event-thread path |

These mutations disrupt callback construction, scheduling, or Future association.

For example, M11 replaces:

```python
cb = functools.partial(self._callback, future)
```

with:

```python
cb = functools.partial(self._callback, None)
```

When the callback executes, it may raise an exception because `_callback()` expects a valid Future. The original Future may consequently remain pending, potentially causing the test to time out.

However, the precise cause of each timeout has not been independently verified.

## 5. Observations

- The Baseline and Enhanced suites produced identical results.
- No additional mutants were confirmed killed by the concurrent tests.
- The timeout mutants primarily affect fundamental callback construction and Future association.
- These faults may affect both single-query and concurrent-query execution.
- Timeout results were recorded separately from confirmed kills.

## 6. Conclusion

The newly added concurrent tests did not produce a measurable improvement for the 13 automatically generated mutants in `_get_future_callback()`.

However, several mutations revealed potential failure modes involving callback scheduling and unresolved Futures. These results highlight the importance of validating Future–Callback association in asynchronous DNS resolution.

Further analysis would be needed to determine whether concurrency-specific fault injection could reveal additional differences between the Baseline and Enhanced test suites.