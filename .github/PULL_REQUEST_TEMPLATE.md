# Pull Request Template

## Description

Please include a summary of the changes and which issue(s) this addresses.

**Fixes:** #[issue_number]

## Type of Change

Please delete options that are not relevant:

- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update
- [ ] Performance improvement
- [ ] Code refactoring
- [ ] Build/CI related changes

## Testing Performed

Please describe the tests that you ran to verify your changes:

- [ ] Tested on Linux (specify distribution: ______)
- [ ] Tested on macOS
- [ ] Tested on BSD
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] No memory leaks (valgrind)
- [ ] Performance tests (if applicable)

**Test Commands:**
```bash
# Commands you ran to test
./configure
make
make check
```

## Checklist

- [ ] My code follows the style guidelines of this project
- [ ] I have performed a self-review of my own code
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] I have made corresponding changes to the documentation
- [ ] My changes generate no new warnings
- [ ] I have added tests that prove my fix/feature is effective
- [ ] New and existing tests pass locally with my changes
- [ ] Any dependent changes have been merged and published
- [ ] I have updated the CHANGELOG if applicable

## Code Quality

- [ ] Code is properly formatted
- [ ] No hardcoded paths or values
- [ ] Error handling is appropriate
- [ ] Memory management is correct (no leaks)
- [ ] Thread safety considered (if applicable)
- [ ] Security implications considered

## Documentation

- [ ] Added/updated inline comments
- [ ] Updated user-facing documentation
- [ ] Updated API documentation (if applicable)
- [ ] Added examples (if applicable)

## Screenshots/Output

If applicable, add screenshots or sample output:

```
# Example output showing the change
```

## Additional Notes

Any additional information that would be helpful for reviewers:
- Design decisions made
- Trade-offs considered
- Future work suggested
- Known limitations

## Breaking Changes

If this PR introduces breaking changes, describe them here:

```
BREAKING CHANGE: Description of breaking change
```

## Related PRs

If this PR depends on or is related to other PRs, list them here:

- Depends on: #PR_NUMBER
- Related to: #PR_NUMBER

---

**Note to Reviewers:** Please focus on:
1. Code correctness and safety
2. Adherence to project style and conventions
3. Performance implications
4. Security considerations
5. Documentation completeness

Thank you for contributing to Argus!
