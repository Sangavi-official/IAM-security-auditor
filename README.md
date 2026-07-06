# IAM Security Auditor — Cloudsplaining + PassRole Blind-Spot Detector

A cloud security tool that scans AWS IAM policy documents for least-privilege
violations and privilege-escalation risk, built on top of
[Cloudsplaining](https://github.com/salesforce/cloudsplaining) (Salesforce,
BSD-3-Clause) with one original addition: a detector for a verified gap in
how Cloudsplaining evaluates `iam:PassRole` resource scoping.

## What this actually does, in one sentence

Cloudsplaining says a policy is only dangerous if `iam:PassRole` has
`Resource: "*"` — this project also flags `Resource: ".../role/*"`, because
that still means "pass any role in the account," which is the same real risk.

---

## 1. Background knowledge you need to actually understand this project

You don't need deep AWS experience, but you should understand these five
concepts before touching the code — they're also exactly what an interviewer
will probe if you mention this project:

1. **IAM policy JSON structure**: every policy is a list of `Statement`s,
   each with an `Effect` (`Allow`/`Deny`), `Action` (what API calls),
   and `Resource` (which specific AWS resources it applies to).
2. **The principle of least privilege**: a principal (user/role) should only
   be able to do exactly what its job requires — nothing more.
3. **`iam:PassRole`**: a special permission that lets a principal hand an
   IAM role to an AWS service (e.g. "launch this EC2 instance *as* this
   role"). It's uniquely dangerous because it lets you "borrow" a more
   privileged role's permissions without being granted them directly.
4. **Privilege escalation paths**: combinations of otherwise-reasonable-looking
   permissions that together let a principal grant themselves more access
   than intended (e.g. `iam:PassRole` + `ec2:RunInstances` lets you launch
   an instance with an admin role attached, then read its credentials from
   the instance's metadata service).
5. **Resource ARN wildcarding**: `arn:aws:iam::123456789012:role/*` is not
   the same restriction as `arn:aws:iam::123456789012:role/one-specific-role`
   — the first still matches every role in the account. This distinction is
   the entire premise of this project.

If those five points make sense, you have what you need.

---

## 2. Requirements

- Python 3.9+
- pip
- No AWS account or credentials needed — everything in this project runs
  against local policy JSON files, not a live account.

---

## 3. Full setup, top to bottom

```bash
# 1. Get the project onto your machine (see Section 6 for how you'll push
#    your own copy to GitHub afterward)
cd iam-security-auditor

# 2. Create a virtual environment (recommended, not required)
python3 -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the automated tests to confirm everything works
python3 -m pytest tests/ -v

# 5. Run the scanner against the included sample policies
python3 combined_scan.py --input-dir sample_policies/

# 6. Run it against a single file, and save a JSON report
python3 combined_scan.py --input-file sample_policies/privesc_passrole_ec2.json --output report.json
```

Expect the test run to show **5 passed**, and the sample-policy scan to show
exactly **one** blind-spot finding total (in `privesc_passrole_ec2.json`) —
the other four policies are either clean or already fully caught by
Cloudsplaining itself, which is the point: this tool is deliberately narrow
and only reports genuinely new findings.

---

## 4. Project structure

```
iam-security-auditor/
├── LICENSE                          # Cloudsplaining's BSD-3-Clause, unmodified
├── NOTICE.md                        # What's original vs. third-party, and why
├── README.md                        # This file
├── requirements.txt
├── combined_scan.py                 # CLI entry point — run this
├── privesc_detector/                # Original module
│   ├── __init__.py
│   └── detector.py                  # The blind-spot detection logic + writeup
├── sample_policies/                 # Test fixtures, including the demo case
│   ├── safe_policy.json
│   ├── privesc_create_access_key.json
│   ├── privesc_multiple_paths.json
│   ├── privesc_passrole_ec2.json               # <- the blind-spot demo
│   └── passrole_fully_unrestricted_control.json # <- proves no false negative
└── tests/
    └── test_privesc_detector.py     # 5 tests incl. 2 false-positive guards
```

---

## 5. Try it yourself in 60 seconds

```bash
python3 combined_scan.py --input-file sample_policies/privesc_passrole_ec2.json
```

You'll see Cloudsplaining report **no privilege escalation** for this
policy, while the blind-spot detector reports one:

```
[BLIND SPOT] CreateEC2WithExistingIP
    Required actions: iam:passrole, ec2:runinstances
    Unrestricted PassRole resource(s): arn:aws:iam::123456789012:role/*
    Why Cloudsplaining misses it: iam:PassRole is scoped to a resource
    pattern that still matches every role in the account...
```

Then run it against the control file to confirm no false positives when
`PassRole` really is unrestricted (Cloudsplaining already catches that one,
so the blind-spot detector correctly reports nothing extra):

```bash
python3 combined_scan.py --input-file sample_policies/passrole_fully_unrestricted_control.json
```

---

## 6. Pushing this as your own GitHub project

1. `git init`, commit everything, create a new (empty) repo on your GitHub
   account, and push — this does **not** need to be a GitHub "Fork" of
   Cloudsplaining, since Cloudsplaining is used here as a pip dependency,
   not copied source code.
2. Keep `LICENSE` and `NOTICE.md` in the repo — this is the actual
   requirement under Cloudsplaining's BSD-3-Clause license (see NOTICE.md
   for exactly what it requires).
3. In your own README intro, say plainly that this builds on Cloudsplaining
   — this is a credibility strength in interviews, not a weakness.

---

## 7. Interview talking points this project gives you

- **Least privilege & IAM fundamentals**: you can explain the five
  background concepts above fluently, with a working tool to point to.
- **Reading and extending an unfamiliar codebase**: you can describe
  reading Cloudsplaining's source to understand exactly how its detection
  worked before deciding what to add — a real day-to-day security
  engineering skill.
- **Verification over assumption**: you can say "I didn't just guess there
  was a gap — I wrote a minimal reproduction, confirmed the behavior, then
  built a targeted fix," which is a strong signal of engineering rigor.
- **False-positive awareness**: your test suite specifically proves the
  detector does *not* flag genuinely scoped permissions (a single named
  role, or a prefix like `role/prod-*`) — showing you understand that a
  security tool that cries wolf gets ignored.

## 8. Honest limitations (know these before an interviewer asks)

- This only checks the `iam:PassRole`-based subset of Cloudsplaining's
  ~60-method privilege-escalation list — it doesn't attempt the other
  categories, since those don't have this specific resource-matching gap.
- It performs static analysis on policy *documents*, not live AWS accounts
  — it doesn't resolve `Condition` blocks, SCPs, or permission boundaries,
  which could further restrict or expand real-world risk.
- The "effectively unrestricted" heuristic (bare `*` as the final path
  segment) is intentionally conservative and simple; more sophisticated
  ARN pattern analysis is possible but was out of scope for a 2-hour build.
