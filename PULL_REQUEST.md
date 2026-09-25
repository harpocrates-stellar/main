# chore(devx): run deployment containers as non-root

## Summary

Hardens all Harpocrates production deployment containers (`harpocrates-backend` and `harpocrates-frontend`) to execute as unprivileged, dedicated non-root users. Prevents container privilege escalation across local, Compose, and Kubernetes environments, reinforcing defense-in-depth at Harpocrates' public deployment boundaries without breaking compatible callers or stored evidence.

Closes #394

---

## Trust-Boundary Implications

Harpocrates isolates cryptographic proof construction and secret generation (in-browser) from untrusted media processing and proof coordination. Running containers as non-root strengthens this architectural separation:

- **TB-4 Deployment Container Execution Boundary (Container Sandbox):**
  - **Backend container (`harpocrates-backend`):** Runs as unprivileged system user `harpocrates` (UID `10001`, GID `10001`). Application files (`/app`) and runtime scratch storage (`/tmp/harpocrates_jobs`) are owned by `10001:10001`. Even under a theoretical memory corruption or RCE flaw in user-space parsers (such as ffmpeg video decoding or image extraction), attacker execution cannot escalate to host root, mount host devices, or inspect root-only filesystems.
  - **Frontend container (`harpocrates-frontend`):** Runs as unprivileged system user `nginx` (UID `101`, GID `101`). Nginx is reconfigured with an unprivileged PID path (`/tmp/nginx.pid`), root directive suppressed, and read-only static web root permissions. Web server vulnerabilities cannot compromise the underlying container sandbox.
  - **Privilege Escalation Block:** Docker Compose stacks and example manifests declare `security_opt: ["no-new-privileges:true"]`, preventing setuid/setgid binary escalation inside the container.
  - **Network Boundary:** All container ports remain strictly unprivileged (`:5050` for backend, `:8080` for frontend, > 1024), eliminating requirements for `CAP_NET_BIND_SERVICE`.

---

## Privacy Implications

- **Zero credential / secret exposure:** Deployment containers and their build definitions contain zero hardcoded secrets, database URLs, witness secrets, or private keys.
- **No telemetry / evidence leakage in logs:** Healthcheck probes (`/health` and `/`) remain URL-only and execute unprivileged without leaking witness values, media paths, or tokens.
- **Fail-safe isolation:** In multi-tenant container hosts or shared virtual machines, non-root execution prevents lateral read access to adjacent tenant filesystems or shared tmpfs storage.

---

## Migration and Compatibility Implications

- **Zero API or wire protocol drift:** The HTTP endpoints, JSON schemas, environment variables (`DATABASE_URL`, `CORS_ORIGINS`, `VITE_*`), and exposed ports (`:5050`, `:8080`) are 100% unchanged.
- **Kubernetes Pod Security Standard compliance:** The images are immediately compliant with the `restricted` profile of Kubernetes Pod Security Standards (`runAsNonRoot: true`, `runAsUser: 10001`, `drop: [ALL]`).
- **Volume storage migration note:** For existing bare-metal / VPS deployments that mounted host directories directly into `/tmp` or custom `HARPOCRATES_STORAGE_DIR`, administrators should ensure host directory ownership is updated to UID `10001`:
  ```bash
  chown -R 10001:10001 /path/to/host/storage
  ```
  Default container runs using container-local `/tmp/harpocrates_jobs` require no manual intervention.

---

## Rollback Plan

- **Container tag rollback:** If a legacy host runtime strictly requires root container execution, deployments can instantly roll back to previous image tags or specify `user: "0:0"` in their compose / pod override without modifying stored evidence or database tables.
- **No persistent state locks:** Non-root execution introduces no state locks, schema migrations, or on-chain contract upgrades.

---

## What Changed

### 1. `backend/Dockerfile`
- Added unprivileged user and group `harpocrates:harpocrates` (UID `10001`, GID `10001`, home `/home/harpocrates`).
- Created and chowned `/tmp/harpocrates_jobs` and `/app` to `harpocrates:harpocrates`.
- Updated `COPY` step with `--chown=harpocrates:harpocrates . .`.
- Switched default runtime user to `USER harpocrates:harpocrates`.
- Retained unprivileged port `EXPOSE 5050` and URL-only `/health` liveness probe.

### 2. `frontend/Dockerfile`
- Configured Alpine nginx runtime to execute as `USER nginx:nginx` (UID `101`, GID `101`).
- Changed PID file path from `/var/run/nginx.pid` to `/tmp/nginx.pid`.
- Commented out the `user nginx;` directive in `/etc/nginx/nginx.conf` to eliminate unprivileged master process warnings.
- Granted ownership of cache, logs, and config directories to `nginx:nginx`.
- Retained unprivileged port `EXPOSE 8080` and SPA liveness probe.

### 3. `docker-compose.yml` & `docker-compose.example.yml`
- Added `security_opt: ["no-new-privileges:true"]` to both `backend` and `frontend` service definitions.
- Confirmed unprivileged port mappings (`:5050`, `:8080`).

### 4. `devx/validate_deployment_containers.py`
- Created dedicated CI verification tool that fail-closes on:
  - Missing `USER` instruction or explicit `USER root` / `USER 0`.
  - Exposed ports < 1024.
  - Embedded secrets, tokens, private keys, or real media paths.
  - Missing `no-new-privileges` in compose files.
  - Privileged flags or root overrides in compose files.
  - Oversized (> 256 KiB), missing, or malformed container files.

### 5. Test Coverage
- **`backend/test_docker_non_root.py`**:
  - Positive tests: non-root user verification for backend (`harpocrates`, 10001) and frontend (`nginx`, 101).
  - Security option checks: `no-new-privileges:true` in compose configs.
  - Negative tests: rejection of root directives, parsing empty/malformed lines, unprivileged port checks.
  - Privacy assertions: absence of credentials and sensitive literals.
- **`devx/test_validate_deployment_containers.py`**:
  - Full suite testing file validation, CLI `--check`, and negative inputs (missing files, empty files, oversized files, root declarations, privileged ports).

### 6. Documentation & Workflows
- **`DEPLOY.md`**: Added Non-Root Container Execution section with UID/GID reference table, Kubernetes securityContext examples, and volume permissions guide.
- **`THREAT_MODEL.md`**: Added assumption D10, trust boundary TB-4, and container mitigation entries for backend and frontend.
- **`.github/workflows/security-scans.yml`**: Added `container-scan` job running `python3 devx/validate_deployment_containers.py --check`.
- **`.github/workflows/release-gate.yml`**: Added validation step before gate checks.
