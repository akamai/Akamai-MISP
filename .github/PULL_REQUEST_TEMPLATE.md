## Description

Please include a summary of the changes and which issue is fixed. Include relevant motivation and context.

Fixes # (issue)

## Type of Change

- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update
- [ ] Code quality improvement
- [ ] Test coverage improvement

## Checklist

### Code Quality
- [ ] My code follows the style guidelines of this project
- [ ] I have performed a self-review of my own code
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] My changes generate no new warnings
- [ ] I have run `ruff check akamai_ioc.py` (if applicable)

### Testing
- [ ] I have added tests that prove my fix is effective or that my feature works
- [ ] New and existing unit tests pass locally with my changes
- [ ] I have run `./validate_module.sh` successfully
- [ ] I have run `python3 tests/test_validation.py` successfully

### Documentation
- [ ] I have made corresponding changes to the documentation
- [ ] I have updated CHANGELOG.md with my changes
- [ ] I have updated README.md if needed

### API Changes (if applicable)
- [ ] I have tested the changes against Akamai API v3
- [ ] I have verified backward compatibility
- [ ] I have updated API endpoint documentation

## Testing Evidence

Please describe the tests you ran to verify your changes:

```bash
# Example:
./validate_module.sh
python3 tests/test_validation.py
pytest tests/ -v
```

**Test results:**
```
[Paste test output here]
```

## Additional Context

Add any other context about the pull request here, such as:
- Screenshots (if UI changes)
- Performance impact
- Security considerations
- Migration notes
