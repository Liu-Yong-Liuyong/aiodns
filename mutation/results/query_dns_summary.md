# command
- mutmut run "*query_dns*" --max-children 1
# query_dns Mutation Testing

- Tool: mutmut 3.8.1
- Target: DNSResolver.query_dns()
- Baseline: 19 killed / 23 mutants (82.61%)
- Enhanced: 19 killed / 23 mutants (82.61%)
- Improvement: 0 percentage points

## Survived Mutants
- M02: Invalid query type error message
- M05: Query class mapping
- M06: Invalid query class error message
- M16: Query class forwarding

## Observation
The three newly added concurrent tests did not improve
the mutation score for query_dns(). The surviving mutants
primarily concern input validation and query class handling,
which are outside the tested concurrent scenarios.
