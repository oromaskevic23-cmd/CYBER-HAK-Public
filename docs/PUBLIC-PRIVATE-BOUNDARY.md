# Public / Private Boundary

This repository is the PUBLIC architecture and documentation surface for CYBER HAK.

It must not publish:

- PRIVATE HANTER runtime source
- internal production infrastructure
- credentials
- API keys
- access tokens
- passwords
- private keys
- seed phrases
- private Audit Ledger records
- private authorization material
- sensitive incident evidence
- customer/user private data

Canonical classifications:

PUBLIC
PRIVATE
SECRET
RESTRICTED

A Git commit does not automatically declassify information.

Public architecture documentation does not prove PRIVATE runtime deployment.

Architecture ≠ Specification  
Specification ≠ Implementation  
Implementation ≠ Testing  
Testing ≠ Runtime Verification  
Runtime Verification ≠ Production Authorization
