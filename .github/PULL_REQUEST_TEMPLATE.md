## Summary

Describe the problem and the user-visible result.

## Design and risk

- What files and trust boundaries are affected?
- How does the change behave on timeout, malformed input, restart, and partial failure?
- Does it change protocol compatibility, privileges, adapter state, or licensing?

## Validation

- [ ] `cmake --build build --config Release --parallel`
- [ ] `ctest --test-dir build -C Release --output-on-failure`
- [ ] Relevant focused or GUI tests were run.
- [ ] Any unavailable test (for example, elevated Wintun E2E) is explained below.

## Review checklist

- [ ] The diff is limited to the stated problem.
- [ ] New logs and errors do not expose secrets or private data.
- [ ] Documentation and tests match the implementation.
- [ ] Performance and failure claims are based on measurements from this build.
- [ ] I have not represented this change as an audit, certification, or support commitment.

## Notes

Include test output summaries, compatibility notes, and follow-up work. Do not
paste credentials, tunnel secrets, private keys, or exploit details.
