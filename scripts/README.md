// Purpose: Document demo scripts and usage flags.
// Governance scope: Documentation only; no protocol changes.
// Dependencies: None.
// Invariants: Keep instructions aligned with live CLI behavior.

# Demo Scripts

## Governed Lifecycle

Windows PowerShell:

```powershell
./scripts/demo-governed-lifecycle.ps1 -Clean
```

POSIX shell:

```bash
./scripts/demo-governed-lifecycle.sh --clean
```

This path exercises proposal submission, voting, timelock, and activation.

## API Surface

Windows PowerShell:

```powershell
./scripts/demo-api-surface.ps1 -Clean
```

POSIX shell:

```bash
./scripts/demo-api-surface.sh --clean
```

This path exercises status, block, tx, and receipt endpoints.
