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

## Sprint 005 — Read-only enforcement evidence

The repository includes an additional safe, **read-only** configuration inspector:

```sh
node tools/github-ruleset-readback.mjs --repo oromaskevic23-cmd/CYBER-HAK-Public
```

It calls GitHub `GET /repos/{owner}/{repo}/rulesets` and the individual ruleset read endpoint. It never sends a POST, PATCH or DELETE and does not consume an administrative write token. An optional Owner-controlled read token for a private repository may be set in `GH_RULESET_READ_TOKEN`; do not paste tokens in chat or commit them.

The only positive receipt is `ACTIVE_RULESET_CONFIGURATION_VERIFIED` after the complete GitHub ruleset object matches the expected `main` branch, required check, no configured bypass actors and PR policy. The receipt explicitly states `actualMergeDenialTested:false`: API configuration is **not** a substitute for the separate negative PR test demonstrating that GitHub rejects a failing check.

A returned 403/404/500, absent or mismatched ruleset, incomplete pagination or malformed API result is `ACCESS_DENIED`, `NOT_FOUND_OR_INACCESSIBLE`, `UNAVAILABLE` or another blocked/unverified status — **never** evidence that branch protection is active. The command returns exit code 2 when protections are not confirmed, without changing the repository. Existing administrative enrollment still requires the Owner-controlled interactive session and plan permissions described above.

## SPRINT 006 — GitHub Actions app provenance and race resistance

The mandatory Enterprise Error Gate is pinned to **GitHub Actions integration ID `15368`**, verified from the real successful check-run API record on the [owned CYBER HAK commit](https://github.com/oromaskevic23-cmd/CYBER-HAK-Public/actions/runs/41315712042/job/124875177241). GitHub's documented required-status-check rule supports an `integration_id`; the policy requires this exact source rather than trusting any status with the same human-readable context.

The Owner-only ruleset installer now verifies that the latest successful main-branch check run comes from the matching `github-actions` app ID and the exact repository's Actions job URL. It rereads `main` immediately before writing the ruleset and after readback; a branch race is reported as unverified rather than a false success. A successful ruleset API readback is now explicitly `ACTIVE_CONFIGURATION_VERIFIED_NEGATIVE_PR_PENDING` — GitHub blocking an intentionally failing PR still requires a separate independent negative acceptance test.

No administrative settings were changed by this sprint. The connected GitHub App still lacks Administration:write, and the Owner-only installer must run interactively under authorized GitHub plan capabilities. Never paste a GitHub token into chat.
