# Debugging log

A tidy README makes a lab look like it ran on the first try. This one didn't —
not on macOS (Apple Silicon) with a current Falco and kernel. Below is every
wall we hit and how we got past it. Each was diagnosed **live against a running
`kind` cluster**, roughly in the order we hit them.

---

### 1. Falco crash-looped immediately (`scap_init` failed)
- **Symptom:** the Falco pod went straight to `CrashLoopBackOff`; the log ended with `Error: Initialization issues during scap_init` and nothing else — not even Falco's startup banner.
- **Diagnosis:** the node runs an **aarch64 / kernel 6.12** LinuxKit VM. Falco **0.38.2**'s bundled modern-eBPF probe (mid-2024) couldn't initialize on it — an old-probe / newer-kernel mismatch, a known class of CO-RE failure. `dmesg` showed no verifier rejection, so it was failing before loading any program.
- **Fix:** bumped the image to **Falco 0.40.0**, whose probe loads cleanly. (The legacy `ebpf` driver is *not* a usable fallback here — it needs kernel headers Docker Desktop's VM doesn't ship.)

### 2. `falcoctl` couldn't write the read-only config
- **Symptom:** `ERROR open /etc/falco/falco.yaml: read-only file system` on every start.
- **Diagnosis:** the image entrypoint runs `falcoctl driver config`, which tries to write the chosen driver back into `falco.yaml` — but we mount that file from a ConfigMap, so it's read-only.
- **Fix:** `SKIP_DRIVER_LOADER=yes`. modern-eBPF is compiled into the Falco binary, so the driver-loader has nothing to do anyway.

### 3. Alerts had no pod name (`k8s.pod.name=<NA>`)
- **Symptom:** detections fired, but every alert showed `pod=<NA>` — so the responder had nothing to isolate.
- **Diagnosis (two parts):** (a) Falco 0.37+ removed the built-in Kubernetes API client; pod metadata now comes from the container runtime. (b) Our deliberately-minimal `falco.yaml` had *replaced* the image default and dropped the `container_engines` block that enables CRI lookups.
- **Fix (first attempt):** re-declared `container_engines.cri` pointing at the mounted containerd socket. This worked… sometimes. See #6.

### 4. The `--cri` flag doesn't exist in Falco 0.40
- **Symptom:** added `--cri /host/run/...` as a container arg → `Error: Option 'cri' does not exist`, back to CrashLoop.
- **Diagnosis:** that CLI flag was removed; socket configuration moved into `falco.yaml` (`container_engines.cri.sockets`).
- **Fix:** reverted the arg and configured the socket in the config file instead.

### 5. Synchronous enrichment killed every event
- **Symptom:** with `disable_async: true` (to force metadata to be present before evaluating a rule), Falco produced **zero** alerts.
- **Diagnosis:** synchronous mode blocks the event thread on each CRI metadata fetch, and that fetch is slow on kind's containerd — so throughput collapsed to nothing.
- **Fix:** keep `disable_async: false`. (Which left us with async's timing problems — see #6.)

### 6. Pod-name enrichment was fundamentally unreliable — *the key turn*
- **Symptom:** even configured correctly, only a fraction of alerts carried a pod name — measured **~2 of 21** over 90 seconds, in a brief window that went cold again.
- **Diagnosis:** Falco's async CRI enrichment on this platform is slow *and* volatile. No amount of cache-warming made it dependable, and the sync alternative was #5.
- **Fix:** **stop depending on it.** Falco always populates `container.id` (derived from the cgroup, synchronously). The responder now maps `container.id → pod` itself via `kubectl get pods`. Deterministic — and it doubles as the noise filter (#7). We then deleted the `container_engines` block *and* the containerd socket mount entirely; `container.id` doesn't need either.

### 7. Phantom shells we never ran
- **Symptom:** "Shell Opened In Container" alerts firing every ~5 seconds, with no pod name.
- **Diagnosis:** Falco watches the whole node through the shared kernel, so it also sees **Docker Desktop's own internal containers** — a registry health-probe running `wget` on a loop — which aren't Kubernetes pods.
- **Fix:** the kubectl-based resolution (#6) filters them for free — a non-pod `container.id` matches nothing, so the responder ignores it.

### 8. `make demo` fired before Falco was watching
- **Symptom:** running `make demo` right after `make up` detected nothing.
- **Diagnosis:** `kubectl rollout status` returns when the Falco **pod** is Ready, but the eBPF **probe** attaches ~10–15 s later. The attack happened in that gap.
- **Fix:** `make up` now actively probes until Falco is *capturing* (triggers a shell, waits for the detection to appear) before it prints "Ready."

### 9. Detections appeared seconds late
- **Symptom:** a snapshot `make demo` (read the log right after attacking) often came back empty — yet the same alerts showed up moments later.
- **Diagnosis:** Falco **block-buffers its stdout** (no TTY in a container), so an alert can take several seconds to surface in `kubectl logs`.
- **Fix:** `make demo` now **streams** (`kubectl logs -f`) through the responder for the duration of the attack instead of taking a single snapshot.

### 10. Warm-up alerts bleeding into the demo
- **Symptom:** the probe-readiness check (#8) triggers its own shells, which occasionally showed up in `make demo`'s output.
- **Fix:** a short drain after the readiness check lets those age out of the log, and `make demo` streams from "now," so only the real attack is shown.

---

## Preemptive hardening (issues we designed around)

- **Control-plane toleration** — a default `kind` cluster is a single control-plane node; a node-level security agent must tolerate its taint (and should run on every node anyway), or the DaemonSet schedules zero pods.
- **Self-contained rules** — we define the handful of macros we need inline and load *only* our two rules, instead of Falco's ~100 defaults, which would otherwise bury the demo in unrelated alerts (starting with Falco's own privileged pod).
- **`.gitignore`** — the original skeleton ignored `demo.gif`, which would have silently broken the README's embedded demo. Removed.

---

## The throughline

Two lessons paid for the whole exercise:

1. **Match your agent to your kernel.** An eBPF probe is compiled against kernel assumptions; an old agent on a new kernel fails in opaque, bannerless ways.
2. **Prefer the deterministic signal over the convenient one.** Falco offers a tidy `k8s.pod.name` field — but on this platform it's unreliable. The humble `container.id` is *always* there, and building the response on that turned a flaky demo into a dependable one.
