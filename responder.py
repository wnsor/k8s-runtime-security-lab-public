"""
responder.py — read Falco's JSON alerts from stdin and isolate the offending pod.

Pipe Falco's log stream in:

    kubectl logs -n falco -l app=falco -f | python3 -u responder.py

Falco reliably tags every alert with the *container ID*; we map that to a
Kubernetes pod with kubectl. (Falco can also fill in k8s.pod.name itself, but
that enrichment is asynchronous and unreliable on kind — so we resolve it
ourselves. It doubles as a noise filter: anything that isn't a real pod, like
Docker Desktop's own containers that Falco sees through the shared kernel,
simply won't match.) High-priority alerts then "isolate" the pod — a safe no-op
print by default. Standard library only.
"""
import json
import subprocess
import sys

# Falco writes priorities capitalized in its JSON output. Act on these.
ACT_ON = {"Emergency", "Alert", "Critical", "Error", "Warning"}

_cache = {}   # container.id -> (namespace, pod) or None, resolved once each


def pod_for(cid: str):
    """Map a Falco container.id (a short prefix) to (namespace, pod), or None."""
    if not cid:
        return None
    if cid not in _cache:
        _cache[cid] = _resolve(cid)
    return _cache[cid]


def _resolve(cid: str):
    try:
        out = subprocess.run(
            ["kubectl", "get", "pods", "-A", "-o", "json"],
            capture_output=True, text=True, timeout=10,
        ).stdout
        items = json.loads(out).get("items", [])
    except Exception:
        return None
    for p in items:
        for st in p.get("status", {}).get("containerStatuses", []):
            full = st.get("containerID", "").split("://")[-1]   # containerd://<64-hex>
            if full and full.startswith(cid):
                m = p["metadata"]
                return (m.get("namespace", "default"), m["name"])
    return None


def isolate(namespace: str, pod: str) -> None:
    """Respond to a confirmed threat. No-op by default — prints what it WOULD do."""
    print(f"    [RESPONSE] would isolate pod={pod} ns={namespace}")
    # Make it real by uncommenting (deleting the pod is bluntest; a deny-all
    # NetworkPolicy is gentler):
    # subprocess.run(["kubectl", "delete", "pod", pod, "-n", namespace], check=False)


def handle(alert: dict) -> None:
    cid = (alert.get("output_fields") or {}).get("container.id")
    who = pod_for(cid)
    if not who:
        return  # host process or non-Kubernetes container — nothing to isolate
    namespace, pod = who
    priority = alert.get("priority", "")
    rule = alert.get("rule", "unknown rule")
    print(f"[ALERT] {priority}: {rule}  (pod={pod} ns={namespace})")
    if priority in ACT_ON:
        isolate(namespace, pod)


def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            alert = json.loads(line)
        except json.JSONDecodeError:
            continue  # Falco's plain-text startup logs aren't JSON — skip them
        if "rule" in alert:       # a rule alert, not some other JSON log line
            handle(alert)


if __name__ == "__main__":
    main()
