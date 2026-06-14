# Threat Index — EKS Study App

An interactive register of how web applications get compromised — the **OWASP Top 10:2025**
plus **cloud / Kubernetes / network** exposures — each ranked by threat level with *how it's
exploited*, *how to fix it*, and *how to harden* against it.

It's also a deliberately small, real full-stack app built to **study the full EKS lifecycle**:
container build, Deployment, Service, Ingress, HPA, ConfigMap, Secret, and RBAC.

Target cluster from your setup: **`prashanth-pgr` in `ap-south-1`**, terminal **Git Bash on Windows**.

---

## 1. Why these choices (the decisions you asked about)

### Language / stack — Node.js, zero dependencies
You chose Node.js full-stack. The server (`server.js`) uses **only Node built-ins** — no Express,
no npm packages. That's intentional:

- **Tiny supply-chain surface.** A security app that pulls 200 transitive npm packages would be
  ironic given A03:2025 (Software Supply Chain Failures). Zero deps = nothing to audit.
- **Tiny, fast image.** Built on `distroless/nodejs20:nonroot` → small image, no shell, runs as
  uid 65532 by default. Good for fast pulls and fast pod startup when the HPA scales.
- **Real backend to study.** It exposes an API, health probes, config injection, and a CPU-burn
  endpoint — enough surface to exercise every EKS concept on your roadmap.

How the language options compare for *this* purpose:

| Option | Image size | HPA load test | Edit speed | Notes |
|---|---|---|---|---|
| **Node.js (chosen)** | small (~120 MB distroless) | easy (`/api/burn`) | fast | full-stack, you picked it |
| Go | tiny (~15 MB) | easy | medium | best image, most K8s-native |
| Python/FastAPI | medium (~150 MB) | easy | fastest | most readable |
| Static + nginx | smallest | trivial only | n/a | no real backend to study |

### Single source of truth for the data
The dataset lives once, embedded in `public/index.html` inside a
`<script id="vuln-data" type="application/json">` block (the pattern frameworks like Next.js use
with `__NEXT_DATA__`). The server **reads that block** and serves it at `/api/vulnerabilities`.
The page prefers the live API (proving the wiring on the cluster) and falls back to the embedded
copy when run standalone — so it works both ways with no duplication.

---

## 2. What's in the box

```
threat-index/
├── server.js              # zero-dep Node server (static + API + health + config + burn)
├── package.json
├── public/index.html      # self-contained dashboard (canonical dataset embedded)
├── Dockerfile             # multi-stage, distroless, non-root
├── .dockerignore
└── k8s/
    ├── 00-namespace.yaml   # namespace + restricted Pod Security Standard
    ├── 01-configmap.yaml   # non-secret config (env)
    ├── 02-secret.yaml      # secret (env) + KMS teaching note
    ├── 03-deployment.yaml  # hardened: probes, resources, securityContext
    ├── 04-service.yaml     # ClusterIP
    ├── 05-ingress.yaml     # ALB ingress
    ├── 06-hpa.yaml         # CPU autoscaling 2→6
    └── 07-rbac.yaml        # least-privilege SA + Role + RoleBinding
```

Endpoints: `/` (UI), `/api/vulnerabilities`, `/api/config`, `/api/burn?ms=2000`, `/healthz`, `/readyz`.

---

## 3. Run it locally first

```bash
cd threat-index
node server.js
# open http://localhost:8080
```

The badge top-right will read **"API live"** because the page reached its own backend.

---

## 4. Build and push to ECR

```bash
# set these once
export AWS_REGION=ap-south-1
export ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
export REPO=threat-index
export IMAGE=$ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/$REPO:v1

# create the repo (first time only)
aws ecr create-repository --repository-name $REPO --region $AWS_REGION || true

# log in, build, push
aws ecr get-login-password --region $AWS_REGION \
  | docker login --username AWS --password-stdin $ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com
docker build -t $IMAGE .
docker push $IMAGE

echo "Image: $IMAGE"
```

Then put that image into the Deployment:

```bash
# replace the placeholder in k8s/03-deployment.yaml
sed -i "s#REPLACE_WITH_YOUR_ECR_IMAGE:v1#$IMAGE#" k8s/03-deployment.yaml
```

---

## 5. Prerequisites on the cluster

```bash
# metrics-server — required for the HPA to read CPU
kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml
kubectl -n kube-system rollout status deploy/metrics-server

# AWS Load Balancer Controller — required for the ALB Ingress (05-ingress.yaml)
# If you don't have it yet, you can skip the Ingress and reach the app via:
#   kubectl -n threat-index port-forward svc/threat-index 8080:80
```

Installing the ALB controller is its own exercise (IRSA role + Helm chart). If you'd rather not
yet, use `port-forward` or temporarily switch the Service to `type: LoadBalancer` like you did for
nginx earlier.

---

## 6. Deploy (apply in order)

```bash
kubectl apply -f k8s/00-namespace.yaml
kubectl apply -f k8s/01-configmap.yaml
kubectl apply -f k8s/02-secret.yaml
kubectl apply -f k8s/07-rbac.yaml
kubectl apply -f k8s/03-deployment.yaml
kubectl apply -f k8s/04-service.yaml
kubectl apply -f k8s/06-hpa.yaml
kubectl apply -f k8s/05-ingress.yaml   # only if the ALB controller is installed

kubectl -n threat-index get pods,svc,hpa,ingress
```

Get the public URL (once the ALB is provisioned, ~2–3 min):

```bash
kubectl -n threat-index get ingress threat-index -o jsonpath='{.status.loadBalancer.ingress[0].hostname}'; echo
```

---

## 7. Study exercises (mapped to your roadmap)

These line up with the sequence you're working through.

**Secrets & ConfigMaps** — verify env injection without exposing the secret value:
```bash
kubectl -n threat-index port-forward svc/threat-index 8080:80 &
curl -s localhost:8080/api/config
# appEnvironment + featureBanner come from the ConfigMap;
# apiKeyConfigured:true proves the Secret mounted — but the value is never returned.
```
Then inspect how K8s stored it (base64, *not* encrypted):
```bash
kubectl -n threat-index get secret threat-index-secret -o jsonpath='{.data.API_KEY}' | base64 -d; echo
```
Teaching point: that's why production needs EKS envelope encryption (KMS) + Secrets Store CSI.

**Ingress** — compare ALB (cloud-native, L7 at the edge) vs an NGINX ingress controller
(portable, runs in-cluster). The Service stays `ClusterIP` either way; only the Ingress changes.

**Persistent Volumes** — this app is stateless by design (good practice). To practice PVs, add a
sidecar or a small stateful component (e.g. a request-counter writing to an EBS-backed PVC via the
EBS CSI driver) and observe `PersistentVolumeClaim` → `PersistentVolume` binding.

**HPA** — watch it scale under load:
```bash
# terminal 1
kubectl -n threat-index get hpa threat-index -w
# terminal 2 — generate load
for i in $(seq 1 200); do curl -s "localhost:8080/api/burn?ms=4000" >/dev/null & done
```
Watch replicas climb toward 6, then settle back after the 120s scale-down window.

**RBAC** — confirm the ServiceAccount is scoped to read-only pods in one namespace:
```bash
kubectl auth can-i list pods    --as=system:serviceaccount:threat-index:threat-index-sa -n threat-index   # yes
kubectl auth can-i delete pods  --as=system:serviceaccount:threat-index:threat-index-sa -n threat-index   # no
kubectl auth can-i list secrets --as=system:serviceaccount:threat-index:threat-index-sa -n threat-index   # no
```

---

## 8. A few decisions left for you

These are genuine choices worth thinking through as part of the study — each has a tradeoff:

1. **Ingress controller:** ALB (managed, L7, AWS-native, costs a load balancer) vs NGINX
   (portable, one LB for many ingresses, you run it). For learning AWS networking, ALB; for
   portability, NGINX.
2. **Cluster endpoint:** keep the API server public (with CIDR restriction) or go private? The app
   register's first infra entry argues for private — a good thing to actually try and feel the
   tradeoff with your Git Bash access.
3. **Credentials:** node instance role (simple, shared by all pods) vs IRSA per ServiceAccount
   (least privilege). The RBAC file has the IRSA annotation commented in to try next.
4. **HPA signal:** CPU (set up here) vs a custom/external metric (e.g. requests/sec via Prometheus
   Adapter) — the more realistic production approach.
5. **Registry:** ECR (integrated IAM, in-region pulls) vs Docker Hub (simpler, rate-limited).

---

## 9. Cleanup

```bash
kubectl delete namespace threat-index
# ECR repo, if you want it gone:
aws ecr delete-repository --repository-name threat-index --region ap-south-1 --force
```

---

## 10. Production hardening checklist (beyond the study setup)

- Enable **EKS Secrets envelope encryption** with a KMS key; move secrets to Secrets Manager + CSI driver.
- **Sign images** (cosign) and verify at admission (A03/A08).
- Add a **default-deny NetworkPolicy** per namespace (the "Missing Network Policies" entry).
- Restrict the **cluster endpoint** and **node security groups** (the K8s/SG entries).
- Turn on **control-plane audit logs, CloudTrail, GuardDuty** (A09).
- Run **kube-bench / kubescape** against CIS benchmarks in CI (A02).

The app you just deployed is, in effect, a checklist of the things to do to the platform it runs on.
