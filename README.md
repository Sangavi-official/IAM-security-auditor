# IAM Security Auditor

Hi, I am Sangavi. This is my cloud security project. I built it while doing my
MSc in AI and Cybersecurity. I like to explain in the
same way I understood it myself.

## What is this project about

AWS uses something called IAM policies. A policy is a small JSON file that
says who can do what in the cloud. If a policy gives too much power, an
attacker can misuse it. This is called privilege escalation.

There is a famous open source tool called
[Cloudsplaining](https://github.com/salesforce/cloudsplaining) from Salesforce.
It reads IAM policies and warns you about risky ones. My project uses
Cloudsplaining as a base and adds one extra check that Cloudsplaining misses.

## The gap I found (the innovative part)

AWS has a permission called `iam:PassRole`. It lets you attach a role to a
service like EC2. If you can pass ANY role, you can pass an admin role to a
server you control. That is a full account takeover path.

Cloudsplaining only raises an alarm when the policy says `Resource: "*"`.
But a policy can also say `Resource: "arn:aws:iam::123456789012:role/*"`.
That looks more specific. It is not. The `role/*` at the end still matches
every single role in the account. Same risk, different spelling.

Cloudsplaining stays silent for this case. My detector catches it. That one
small check is the whole point of this project. It is small, but it is a
real blind spot, and I proved it with a working demo policy.

## What I actually did, step by step

1. I read how IAM policies work. Statements, Effect, Action, Resource.
2. I ran Cloudsplaining on some risky sample policies and watched what it
   catches and what it does not.
3. I wrote a small test policy with PassRole scoped to `role/*` and saw
   Cloudsplaining report nothing. That confirmed the gap.
4. I wrote my own module `privesc_detector/` that checks for this pattern.
5. I wrote 5 pytest tests. Two of them make sure my detector does NOT flag
   safe policies. False positives make a security tool useless, so I tested
   for that on purpose.
6. I made a CLI script `combined_scan.py` that runs Cloudsplaining and my
   detector together on any policy file or folder.
7. I pushed everything to GitHub with proper license credit to Cloudsplaining.

## Result

- All 5 tests pass.
- Scanning the 5 sample policies gives exactly 1 blind-spot finding, in
  `privesc_passrole_ec2.json`. Cloudsplaining says that policy is fine.
  My detector shows it is not.
- The control file `passrole_fully_unrestricted_control.json` proves my
  detector does not repeat what Cloudsplaining already catches.

## How to run it (beginner friendly)

You do not need an AWS account. Everything runs on local JSON files.

```bash
# 1. clone and enter the folder
git clone <this-repo-url>
cd iam-security-auditor

# 2. make a virtual environment (keeps packages clean)
python3 -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate

# 3. install the two dependencies
pip install -r requirements.txt

# 4. run the tests. you should see: 5 passed
python3 -m pytest tests/ -v

# 5. scan all sample policies. you should see: 1 blind-spot finding
python3 combined_scan.py --input-dir sample_policies/
```

## How to verify what is happening

Open `sample_policies/privesc_passrole_ec2.json` and look at the Resource
line. It ends with `role/*`. Now run:

```bash
python3 combined_scan.py --input-file sample_policies/privesc_passrole_ec2.json
```

Cloudsplaining section says no privilege escalation. My detector section
prints a `[BLIND SPOT]` finding and explains why. That side-by-side output
is the proof. You can also change `role/*` to `role/one-exact-role` in the
file, run it again, and watch the finding disappear. That is how I verified
it manually myself.

## What I learned

1. A wildcard hiding at the end of an ARN can be just as dangerous as a full `*`, and tools can miss it.
2. Testing that a security tool stays quiet on safe input is as important as testing that it fires on bad input.
3. Reading someone else's open source code to find one exact gap taught me more than writing everything from scratch.

## How this helps my career

I want to work in SOC and cloud security roles. This project shows I can
read real IAM policies, understand privilege escalation, extend an existing
open source security tool, and back my claim with tests. These are things I
can explain confidently in an interview because I did each step myself.

## Where can this be used

- Reviewing IAM policies before they go live in a company AWS account
- CI pipelines, to block risky policies automatically
- Security audits and cloud pentest reports
- Learning material for anyone studying IAM privilege escalation

## Credits and license

This project is built on top of Cloudsplaining by Salesforce, used as a pip
dependency under the BSD-3-Clause license. The `LICENSE` and `NOTICE.md`
files explain exactly what is original here and what belongs to
Cloudsplaining. The `privesc_detector/` module, the sample policies, the
tests and this README are my own work.
