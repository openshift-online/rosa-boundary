# ROSA Boundary monorepo wiki scope

Maintain **one repository-root `openwiki/`** for both ROSA Boundary and the
Trusted Actions component at `components/trusted-actions/`. On the first update
after the source-import merge, add Trusted Actions architecture, API,
authorization, execution, audit, deployments, and testing to the root wiki's
navigation and evidence-backed pages. Preserve accurate Boundary coverage.

Trusted Actions has its own Go module, container, Terraform roots, and security
model. Explain its relationship to Boundary without conflating their runtime,
credentials, audit paths, or deployment states. Verify current code and tests;
the old `rosa-trusted-actions` wiki was generated for a different repository
layout and is **not** imported as source, Claims, or a second wiki. Do not infer
that the source import has switched live HCP, Prow, or Konflux integrations.
