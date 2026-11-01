# CYBER HAK — Owner-Controlled GitHub Main Branch Protection

**Status:** ruleset policy-as-code and safe one-repository installer. **Not an installed ruleset until verified via GitHub API.**

Copyright (c) 2026 Alexander Nikolaevich Romaskevich (RomaskevicH).

## Why Owner administration is a separate action

The connected GitHub App supports code access but does not have repository
Administration:write permission for Rulesets. On 2026-11-01, the readable
ruleset inventories of CYBER-HAK-Public and CONSTRUCTOR-AI returned empty.
Reading HANTER-Private rulesets returned HTTP 403 with a GitHub Pro / private
repo plan restriction.

Never make a private repository public to avoid paying for a GitHub plan.
Public repository rulesets are supported on GitHub Free; rulesets for private
repositories require a qualifying GitHub plan. Any upgrade is a separate
Owner financial decision under FREE_ONLY. ChatGPT Plus is not GitHub Pro.

Official docs:
https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets
https://docs.github.com/en/rest/repos/rules

## Proposed policy

The main-ruleset.mjs policy requires:

- Exact refs/heads/main target.
- ACTIVE enforcement with no configured bypass actors.
- No branch deletion or force-push.
- Changes to main must go through a pull request.
- Mandatory check: enterprise-quality / enterprise-error-gate.
- Strict status-check freshness (up-to-date with base).
- Squash merges only and required review thread resolution.

**Solo-owner limitation:** required approving reviews are initially zero,
so a single project Owner can still merge a successful CI PR. With
independent maintainers, separately enable CODEOWNERS and required
reviews. Never lock the only maintainer out by demanding approval
that nobody else can legally provide.

The required check name is from an actual successful GitHub Actions job.
Product-specific checks must be separately reviewed before becoming
required; this program never silently edits an existing ruleset.

## Offline dry-run: no API call and no token

    node tools/github-ruleset-controller.mjs --plan --repo oromaskevic23-cmd/CYBER-HAK-Public

The output is PROPOSED_NOT_INSTALLED, never proof of enforcement.

## Owner-only installation

On an Owner-controlled trusted interactive workstation, obtain a short-lived
fine-grained GitHub token scoped to **one repository** with Administration:write
and Contents:read. Do not transmit tokens to ChatGPT, GitHub issues, CI,
public repositories or command-line arguments. Do not use this step when
the GitHub plan does not authorize Rulesets for the repository visibility.

    export GH_ADMIN_TOKEN="<LOCAL_TOKEN_ON_TRUSTED_OWNER_DEVICE>"
    export CYBER_HAK_RULESET_OWNER_APPROVAL="ACTIVATE_ONE_MAIN_RULESET"
    node tools/github-ruleset-controller.mjs --apply --repo oromaskevic23-cmd/CYBER-HAK-Public
    unset GH_ADMIN_TOKEN CYBER_HAK_RULESET_OWNER_APPROVAL

Do not execute the placeholder literally.

The CLI verifies the exact owner/repository and main branch, checks existing
rulesets, requires a green and current enterprise gate on main, and only then
creates **one** ruleset. It fetches back the actual GitHub object and validates
enforcement, main target, required checks, no-bypass and PR rules before
printing ACTIVE_VERIFIED.

If creation succeeded but readback failed, inspect GitHub Rulesets manually.
It deliberately does not blindly delete, recreate or modify any existing
ruleset. An interactive terminal and explicit Owner confirmation are
required; the --apply path rejects CI and missing admin credentials.

This procedure does not authorize a paid plan, token issuance or any
changes to private-repository visibility.

## Evidence and regression requirements

After a true activation, check GitHub Settings → Rules → Rulesets, and
verify the REST API GET /repos/OWNER/REPO/rulesets/{id}. Test a harmless
failing PR against main and prove it cannot merge, then close the PR.
Store rule ID, time, test run and checks in the PRIVATE Audit Ledger.

Run the standalone tests via npm run verify. Mocked API tests are not
evidence that real GitHub repository administration succeeded.

The mechanism is separate from Strix and from AI Passport, Owner Ed25519,
Guardian Core, Approval Gateway and production runtime governance.
