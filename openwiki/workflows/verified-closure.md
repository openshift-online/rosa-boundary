---
type: workflow
title: Verified investigation closure
description: How Boundary records a close request, drains tasks, verifies a workspace copy, and reports cleanup independently.
tags: [investigations, verification, audit, efs]
verified:
  - by: openwiki/0.9.0
    at: 2026-11-25T19:00:35.491Z
sources:
  - id: openwiki-source-e9906b078522ed0a08c64ff1
    resource: repo://entrypoint.sh
  - id: openwiki-source-f6af557e33982c811eaa2ded
    resource: repo://lambda/create-investigation/close_requests.py
  - id: openwiki-source-53ded000b5419d48efde6aba
    resource: repo://lambda/reap-investigations/close_finalization.py
generated: { by: "pi", at: "2026-11-25T19:00:35.491Z" }
---

# Verified investigation closure

Use `investigation close --status` to distinguish a request from a completed close. `--wait` follows the service's progress; disconnecting from the wait does not cancel its work.

## Request and drain

An accepted close records a request and its stop consent. It is not authority to stop an attached shell: the service rejects an explicit request while a shell is attached, and the finalizer waits if one attaches after acceptance.

The finalizer seals, drains within the consented scope and requires two quiet observations before measuring. Unknown state or a missing workspace cannot establish a verified empty copy.

## Evidence and cleanup

Each verification attempt binds its source manifest, destination copy and verification evidence to the attempt. A task's shutdown sync is not this verification.

A verified receipt records cleanup separately: normal closure retains the EFS directory, and incomplete cleanup remains retryable rather than being reported as completed. Read the reported access-point deletion, directory retention and task-definition counts rather than inferring cleanup from the presence of a receipt alone.

See [investigation lifecycle](investigation-lifecycle.md) for command roles and [audit and logging](../operations/audit-and-logging.md) for the other evidence sources.
