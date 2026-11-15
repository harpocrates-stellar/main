# Frontend Development & Testing

This document details the local equivalent commands used by the `Frontend CI` workflow. All commands must be run from within the `frontend/` directory.

## 1. Install Dependencies
Always use `npm ci` to ensure strict alignment with `package-lock.json`:
```bash
npm ci
```
## 2. Code Linting
Run static analysis to catch syntax and styling errors:
```bash
npm run lint
```
(If errors arise, try running npm run lint -- --fix to auto-correct styling issues).

## 3. Production Build
Verify the application compiles and bundles successfully for production:
```bash
npm run build
```
(This performs TypeScript type-checking and Vite compilation. It will fail if there are any TypeScript or bundling errors).

## 4. Stage Focus Restoration & Accessible Progress Updates
`StudioView` (`frontend/src/views/StudioView.tsx`) and `resolveStageFocusTarget` (`frontend/src/hooks/useEvidence.ts`) manage keyboard focus across processing stage transitions without re-announcing the page on byte-level progress ticks:
- **Surviving control / status heading focus**: stage changes move focus to the active `Cancel` control during busy stages, `Register proof` when `ready` and actionable, the `#studio-evidence-dropzone` picker on `cancelled`, or `#studio-heading` when `registered`, `error`, or registration is blocked — while preserving focus when the operator is actively typing inside an input field.
- **Bounded announcements**: `<section id="studio">` omits whole-page `aria-busy`, and intra-stage `hashProgress` updates update visual byte counters without mutating the polite stage live region or re-focusing the workspace.
