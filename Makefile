.PHONY: help up attack demo logs respond down

CLUSTER := runtime-lab

help:    ## Show this help
	@grep -E '^[a-z]+:.*##' $(MAKEFILE_LIST) | sed -E 's/:.*## /\t/' | expand -t12

up:      ## Create the kind cluster, deploy Falco (DaemonSet) + the demo app
	kind create cluster --name $(CLUSTER)
	kubectl apply -f falco.yaml
	kubectl apply -f app.yaml
	@echo "==> Waiting for Falco and the demo app to come up (first run pulls images)..."
	kubectl rollout status -n falco daemonset/falco --timeout=300s
	kubectl rollout status deployment/demo-app --timeout=120s
	@echo "==> Waiting for Falco's eBPF probe to start capturing (up to ~60s)..."
	@for i in $$(seq 1 20); do \
	  kubectl exec deploy/demo-app -- sh -c true 2>/dev/null || true ; \
	  if kubectl logs -n falco -l app=falco --since=15s 2>/dev/null | grep -q "Shell Opened In Container"; then \
	    echo "    Falco is capturing." ; break ; \
	  fi ; \
	  sleep 3 ; \
	done
	@sleep 12  # let the readiness check's own warm-up alerts flush + age out of the log
	@echo "==> Ready. Run 'make demo' (one terminal), or 'make respond' + 'make attack' (two)."

attack:  ## Trigger the detections (benign, local sandbox only)
	bash attack.sh

demo:    ## One-shot (single terminal): stream alerts through the responder while attacking
	@echo "==> Watching Falco and running the attack (~20s)..."
	@kubectl logs -n falco -l app=falco -f --since=1s 2>/dev/null | python3 -u responder.py & \
	 STREAM_PID=$$! ; \
	 sleep 3 ; \
	 bash attack.sh ; \
	 sleep 12 ; \
	 kill $$STREAM_PID 2>/dev/null || true

logs:    ## Stream raw Falco detections (JSON alerts)
	kubectl logs -n falco -l app=falco -f

respond: ## Stream detections into the auto-responder
	kubectl logs -n falco -l app=falco -f | python3 -u responder.py

down:    ## Delete the kind cluster and everything in it
	kind delete cluster --name $(CLUSTER)
