## Description
Please include a summary of the change, motivation, and context. List any dependencies required for this change.

Fixes #(issue)

## Type of Change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] New detection rule (Sigma / MITRE ATT&CK mapping)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update
- [ ] Performance / Security improvement

## Checklist
- [ ] My code follows the style guidelines of this project
- [ ] I have performed a self-review of my own code
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] I have updated relevant documentation in `docs/`
- [ ] My changes generate no new warnings or errors
- [ ] I have added unit/integration tests that prove my fix is effective or that my feature works
- [ ] All new and existing tests passed:
  - [ ] Backend: `./mvnw test`
  - [ ] Frontend: `npm test && npm run build`
  - [ ] Adversary suite: `node test-lab/run_simulations.js`
- [ ] Any dependent changes have been merged and published in downstream modules
