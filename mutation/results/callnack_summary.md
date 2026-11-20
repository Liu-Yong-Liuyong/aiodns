# command
- mutmut run "*ǁ_callback__mutmut_*"
# `_callback()` Mutation Testing Summary

## 1. Objective

Evaluate whether the newly added concurrent DNS query tests improve fault detection in asynchronous Future completion and DNS error propagation.

## 2. Mutation Target

- File: `aiodns/__init__.py`
- Function: `DNSResolver._callback()`
- Mutation tool: Mutmut 3.8.1
- Total mutants: 8

The function checks whether a Future has already completed, then assigns either a DNS query result or a `DNSError` exception.

## 3. Test Suite Comparison

**Baseline:** Original aiodns test suite, excluding the three newly added concurrent tests.

**Enhanced:** Original aiodns test suite, including the three concurrent tests.

### Mutation Results

| Result | Baseline | Enhanced |
|---|---:|---:|
| Total Mutants | 8 | 8 |
| Killed | 3 | 6 |
| Survived | 4 | 2 |
| Timeout | 1 | 0 |
| Confirmed Kill Rate | 37.50% | 75.00% |

**Confirmed Kill Rate Improvement: +37.50 percentage points.**

The Enhanced suite killed three more mutants than the Baseline, including one mutant previously classified as a timeout.

### Individual Mutant Results

| Mutant | Baseline | Enhanced |
|---|---|---|
| M01 | Timeout | Killed |
| M02 | Killed | Killed |
| M03 | Survived | Killed |
| M04 | Survived | Survived |
| M05 | Survived | Killed |
| M06 | Survived | Survived |
| M07 | Killed | Killed |
| M08 | Killed | Killed |

## 4. Survived-to-Killed Mutant Analysis

### M03 — Incorrect DNS Error Code

Original:

```python
error.DNSError(errorno, pycares.errno.strerror(errorno))
```

Mutant:

```python
error.DNSError(None, pycares.errno.strerror(errorno))
```

The mutation replaces the original DNS error code with `None`.

- Baseline: Survived
- Enhanced: Killed

This indicates that the Enhanced test suite detected a change that the Baseline did not detect in the initial comparison.

### M05 — Missing DNS Error Code Argument

Original:

```python
error.DNSError(errorno, pycares.errno.strerror(errorno))
```

Mutant:

```python
error.DNSError(pycares.errno.strerror(errorno))
```

The mutation removes the original error-code argument and passes only the error message.

- Baseline: Survived
- Enhanced: Killed

This suggests improved detection of incorrect DNS error construction.

### M01 — Timeout to Killed

- Baseline: Timeout
- Enhanced: Killed

The Enhanced suite classified M01 as killed, whereas the Baseline timed out.

The exact cause of this difference requires further investigation. A timeout-to-killed transition is not necessarily equivalent to discovering a previously undetected fault.

## 5. Remaining Survived Mutants

### M04 — Missing Error Message

The mutation changes:

```python
error.DNSError(errorno, pycares.errno.strerror(errorno))
```

to:

```python
error.DNSError(errorno, None)
```

This mutation survived both test suites.

### M06 — Removed Error Message Argument

The mutation changes:

```python
error.DNSError(errorno, pycares.errno.strerror(errorno))
```

to:

```python
error.DNSError(errorno)
```

This mutation also survived both test suites.

These surviving mutants suggest that the selected tests do not fully distinguish the original DNS error-message construction from the mutated implementations.

## 6. Observations and Limitations

- The Enhanced suite increased confirmed kills from 3 to 6.
- M03 and M05 changed from Survived to Killed.
- M01 changed from Timeout to Killed.
- M04 and M06 survived both suites.
- The observed improvements primarily involve DNS error construction and propagation rather than cross-query result association.
- The observed differences should be confirmed using clean, independent mutation runs to eliminate possible cache effects.

Mutmut was configured with `process_isolation = "forkserver"` after a segmentation fault occurred during an earlier run.

## 7. Conclusion

The initial mutation testing results indicate improved fault detection in `_callback()` after adding the concurrent DNS query tests.

The confirmed kill rate increased from 37.50% to 75.00%, with two mutants changing from Survived to Killed and one changing from Timeout to Killed.

These results provide preliminary evidence that the Enhanced test suite can detect additional faults in DNS error handling.

Further verification is required to establish that the observed improvements are reproducible and are directly attributable to the newly added concurrent tests.