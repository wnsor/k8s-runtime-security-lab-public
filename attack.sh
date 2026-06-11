#!/usr/bin/env bash
# Trigger the two detections so you can watch Falco and the responder react.
# Everything here is benign: it runs harmless commands inside the throwaway
# demo pod in your local kind cluster. No exploit code, nothing leaves the box.
set -euo pipefail

echo "==> Waiting for the demo-app pod to be ready..."
kubectl wait --for=condition=Ready pod -l app=demo-app --timeout=60s >/dev/null

POD=$(kubectl get pod -l app=demo-app -o jsonpath='{.items[0].metadata.name}')
echo "==> Target pod: $POD"
echo

echo "==> [1/2] Opening a shell in the container   -> rule: Shell Opened In Container"
kubectl exec "$POD" -- sh -c 'echo "hello from inside the container"'
sleep 2
echo

echo "==> [2/2] Reading a sensitive file           -> rule: Sensitive File Read In Container"
kubectl exec "$POD" -- sh -c 'cat /etc/shadow >/dev/null 2>&1 || true'
sleep 2
echo

echo "==> Done. See the detections with:  make logs     (raw alerts)"
echo "                              or:   make respond  (alerts + auto-isolate)"
