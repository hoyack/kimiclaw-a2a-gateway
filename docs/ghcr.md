# GHCR image and digest

CI builds the existing `Dockerfile` with `load: true`, scans the loaded image and the repository git history for secrets, and, on `main` only after those scans pass, pushes the exact scanned image to `ghcr.io/hoyack/kimiclaw-a2a-gateway`. The `push` job loads the `docker save` tarball from `build-and-scan` (it does not rebuild), re-runs the docker history check and the layer secret scan on that same image, and pushes only if the re-scan is clean. This workflow does not change package visibility.

## When an image is pushed

- A push to `main`, or `workflow_dispatch` on `main`, builds, scans, re-scans, and then pushes.
- The `push` job has `needs: [build-and-scan]` and does not run unless the first scan passes. A finding on the re-scan fails the job with no push.
- Pull requests build and scan only and never push.
- Tags are the full commit SHA and the short SHA. The workflow never tags `latest`.
- Re-running the workflow for the same SHA re-pushes the same tags.
- After a successful push, the job attests build provenance (`actions/attest-build-provenance`) and an SPDX SBOM (`anchore/sbom-action` plus `actions/attest-sbom`) for the pushed digest, and pushes those attestations to GHCR. The push job also has `id-token: write` and `attestations: write` for that. The image itself is still the scanned tarball, not a rebuild.

No new Actions secrets are used. The push job authenticates to GHCR with the built-in `GITHUB_TOKEN` only after the re-scan passes. The build-and-scan job has `contents: read` only.

The read-only token Alamo will use to pull the image is still pending Brandon's answer on which machine account should issue it (and is unused if the package is published public). This workflow does not create or deploy that pull secret.

## How to find the digest

After a successful `docker-build` run on `main` (the push job):

1. Open the run's job summary. It has a line of the form `ghcr.io/hoyack/kimiclaw-a2a-gateway@sha256:…`.
2. Or download the `image-digest` artifact (`image-digest.txt`), which contains the same reference. That artifact is uploaded only when the image was actually pushed.

Alamo should pull by that digest, not by a mutable tag:

```text
ghcr.io/hoyack/kimiclaw-a2a-gateway@sha256:<digest>
```

A pull-request run records scan results in the job summary and does not upload an `image-digest` artifact. A local build digest from a PR is not on GHCR and must not be used to pull.

## Rollback

Revert this PR (or the merge commit on `main`). A pushed image does no harm on its own: nothing deploys it. Cluster apply on Alamo is a separate, later step and is not triggered by this workflow.
