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

## 4. Batch Export Formats: Human-Oriented CSV vs. Machine-Readable JSON
`frontend/src/batchExport.ts` distinguishes between human-oriented spreadsheet exports and machine-readable structured exports (`BATCH_EXPORT_FORMAT_SEMANTICS`):

- **Human-oriented CSV (`exportBatchCSV`)**: Designed for spreadsheet tools (Excel, LibreOffice Calc, Google Sheets). Free-text columns (`File Name`, `Status`, `Tier`, `Chain Status`, `Message`, `Duplicate Of`, `Failure Reason`) pass through `neutralizeSpreadsheetFormula`, which prepends a literal single quote (`'`) whenever a cell starts with `=`, `+`, `-`, `@`, leading tabs/CR/LF, or whitespace-padded formula triggers, and RFC-4180 quotes commas, quotes, CR, and LF. Canonical hexadecimal digest columns (`Video Hash`, `Metadata Hash`, `Source Hash`) and numeric amount columns (`Size (Bytes)`, `Duration (ms)`) are emitted verbatim without prefixing.
- **Machine-readable JSON (`exportBatchJSON`, `exportReceiptCollection`)**: Designed for automated verifiers, audit pipelines, and programmatic consumers. Preserves exact unescaped string values, digests, and numeric fields without `'=…` spreadsheet neutralization.
