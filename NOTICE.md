# Notice of Third-Party Code and Original Additions

## Third-party dependency

This project uses [Cloudsplaining](https://github.com/salesforce/cloudsplaining)
by Salesforce.com, Inc., installed as a normal pip dependency
(`pip install cloudsplaining`, see `requirements.txt`). Cloudsplaining is
licensed under **BSD-3-Clause** (see `LICENSE`, copied unmodified from the
upstream project as required by the license terms). No source code from
Cloudsplaining is copied or modified in this repository -- it is used as
a library.

## Original work in this repository

Everything in `privesc_detector/`, `combined_scan.py`, `tests/`, and
`sample_policies/` was written for this project. Specifically:

- **The finding**: Cloudsplaining's built-in privilege-escalation detector
  (`PolicyDocument.allows_privilege_escalation`) only flags `iam:PassRole`-based
  escalation techniques when the statement's `Resource` is a literal `"*"`.
  Resource patterns like `arn:aws:iam::123456789012:role/*` -- which still
  grant "pass any role in the account" -- are not flagged, even though the
  practical risk is the same. This was found by reading Cloudsplaining's
  source (`cloudsplaining/shared/constants.py`) and verified empirically
  with minimal reproduction policies (see `tests/test_privesc_detector.py`).

- **The detector**: `privesc_detector/detector.py` cross-references
  Cloudsplaining's own `PRIVILEGE_ESCALATION_METHODS` table, filters to the
  PassRole-based subset, and flags only the cases Cloudsplaining's own
  scan did *not* already catch for that policy -- so results are additive,
  not duplicated.

- **Tests**: 5 automated tests, including two specific false-positive
  guards (a single named role, and a prefix-restricted pattern like
  `role/prod-*`, are both correctly left unflagged).

If you use or extend this code, please keep this file and the LICENSE file
intact, and keep crediting Cloudsplaining/Salesforce for the underlying
scanning engine this builds on.
