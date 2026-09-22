# sops-secret-operator

Kubernetes operator that turns SOPS-encrypted `SopsSecret` resources into plain `Secret`s, with a ValidatingAdmissionWebhook enforcing read-permission boundaries on referenced keys.

## Why

- Credentials stay encrypted in git while apps consume them as plain `Secret`s.
- A user can only reference `Secret`s they already have `get` access to — no privilege escalation via the CRD, even across namespaces.

## Prerequisites

- `gpg` and `sops` on your dev box
- Cluster-admin for install
- **cert-manager** on the cluster (the webhook's TLS certs come from it)

## Install

Versions below are pinned to `v0.1.0`; use the [latest release](https://github.com/maeshinshin/sops-secret-operator/releases) for newer.

```sh
# Helm
helm repo add sops-secret-operator https://maeshinshin.github.io/sops-secret-operator
helm install sops-secret-operator sops-secret-operator/sops-secret-operator \
  --namespace sops-secret-operator-system --create-namespace

# Kustomize
make install
make deploy IMG=ghcr.io/maeshinshin/sops-secret-operator:v0.1.0

# Raw manifests
kubectl apply -f https://raw.githubusercontent.com/maeshinshin/sops-secret-operator/v0.1.0/dist/install.yaml
```

Verify: `kubectl -n sops-secret-operator-system get pods` shows the manager `Running`, and `kubectl get crd sopssecrets.sops.maesh.dev` is `Established`.

## Features

- SOPS decryption with PGP (passphrase-protected keys)
- `DeletionPolicy: Delete | Retain`
- `Type` and `Immutable` propagation
- Cross-namespace `keyRef` with webhook-enforced authorization
- Status conditions: `KeyAvailable`, `SecretSynced`, `Ready`

## Usage

The walkthrough uses `my-app` for both the key `Secret` and the `SopsSecret`, with shell variables `$MY_FINGERPRINT` and `$MY_PASSPHRASE` you fill in.

### 1. Create the GPG key

The operator requires a **passphrase-protected** private key. Use a strong passphrase — anyone with `get` on the key `Secret` can decrypt everything if the key has no passphrase.

```sh
gpg --full-generate-key   # when prompted: RSA and RSA, 4096 bits, then passphrase

gpg --list-secret-keys --with-fingerprint   # copy the 40-char fingerprint
export MY_FINGERPRINT=...
export MY_PASSPHRASE=...

gpg --export-secret-keys --armor "$MY_FINGERPRINT" > pgp.key
echo -n "$MY_PASSPHRASE" > passphrase.txt
chmod 600 passphrase.txt
```

### 2. Apply the PGP key `Secret`

The two data key names (`pgp.key`, `passphrase`) are arbitrary — they just have to match step 4.

```sh
kubectl create namespace my-app

kubectl create secret generic pgp-key \
  --from-file=pgp.key=./pgp.key \
  --from-file=passphrase=./passphrase.txt \
  -n my-app
```

`--from-file=KEY=PATH`: left is the Secret data-key name, right is the file on disk.

### 3. Configure sops

Put `.sops.yaml` at the root of your app repo (where the encrypted files live):

```yaml
creation_rules:
  - path_regex: .*\.yaml$
    encrypted_regex: ^(data|stringData)$
    pgp: MY_FINGERPRINT
```

Only `data` / `stringData` get encrypted; `apiVersion`, `kind`, `metadata`, `spec` stay plaintext so the file remains a valid Kubernetes manifest.

### 4. Write and encrypt the `SopsSecret`

```sh
cat <<'EOF' > db-credentials.sopssecret.yaml
apiVersion: sops.maesh.dev/v1alpha1
kind: SopsSecret
metadata:
  name: db-credentials
  namespace: my-app
spec:
  decryption:
    pgp:
      keyRef:
        name: pgp-key
        key: pgp.key
        # namespace: security-team   # cross-namespace; the webhook checks get access
      passphraseRef:
        name: pgp-key
        key: passphrase
        # namespace: security-team
stringData:
  username: changeme   # replace with real values before encryption
  password: replace-me
EOF

sops --encrypt --in-place db-credentials.sopssecret.yaml
```

`stringData` becomes `data` with `ENC[AES256_GCM,...]` values and a top-level `sops:` field carries the PGP-encrypted data key. Commit only the encrypted file.

> `stringData` is for plaintext values. `data` is for pre-base64 values — the operator base64-decodes whatever is there (Kubernetes `Secret` semantics), so put plaintext in `stringData` to avoid surprises.

### 5. Apply and verify

```sh
kubectl apply -f db-credentials.sopssecret.yaml

kubectl get sopssecret db-credentials -n my-app -o jsonpath='{.status.conditions}' | jq .
# expect Ready=True

kubectl get secret db-credentials -n my-app -o yaml
# data.password is base64 of the decrypted plaintext
```

### Cross-namespace key references

See the commented-out alternatives in the step 4 example above. The webhook checks the requestor has `get` on the foreign Secret; users without that access are rejected at admission time.

### Deletion policy

```yaml
apiVersion: sops.maesh.dev/v1alpha1
kind: SopsSecret
metadata:
  name: db-credentials
deletionPolicy: Retain        # sibling of metadata; default: Delete (cascade via OwnerReference)
spec:
  decryption: {...}
stringData: {...}
```

`Retain` keeps the target `Secret` after the `SopsSecret` is deleted.

## Security model

The webhook performs a `SubjectAccessReview` for each referenced `Secret` against the requestor's `UserInfo`. A `SopsSecret` is rejected at admission time if the caller lacks `get` on any of its `keyRef` / `passphraseRef` targets. Read access to the generated target `Secret` is controlled by ordinary namespace RBAC.

If something goes wrong: `kubectl describe sopssecret <name> -n <ns>` shows the failure `Reason` (`DecryptError`, `KeyUnavailable`, `ApplyFailed`).

## Development

```sh
make test          # unit + envtest
make test-e2e      # kind cluster + cert-manager
make lint

make manifests generate
kubebuilder edit --plugins=helm/v2-alpha --force   # updates dist/chart
```

Tag pushes (e.g. `v0.1.0`) trigger `.github/workflows/release.yml` to build & push the image and publish the chart. CHANGELOG is managed by `release-please` on every push to `main`.

## License

Apache License 2.0.
