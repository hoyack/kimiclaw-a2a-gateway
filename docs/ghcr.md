# GHCR image and digest

CI builds the existing `Dockerfile` and, on `main` only, pushes the image to `ghcr.io/hoyack/kimiclaw-a2a-gateway`. The package is intended to stay private. This workflow does not change package visibility.

## When an image is pushed

- A push to `main`, or `workflow_dispatch` on `main`, builds and pushes.
- Pull requests build only and never push.
- Tags are the full commit SHA and the short SHA. The workflow never tags `latest`.
- Re-running the workflow for the same SHA re-pushes the same tags (idempotent).

No new Actions secrets are used. The job authenticates to GHCR with the built-in `GITHUB_TOKEN`.

The read-only token Alamo will use to pull the image is still pending Brandon's answer on which machine account should issue it. This workflow does not create or deploy that pull secret.

## How to find the digest

After a successful `docker-build` run on `main`:

1. Open the run's job summary. It has a line of the form `ghcr.io/hoyack/kimiclaw-a2a-gateway@sha256:…`.
2. Or download the `image-digest` artifact (`image-digest.txt`), which contains the same reference.

Alamo should pull by that digest, not by a mutable tag:

```text
ghcr.io/hoyack/kimiclaw-a2a-gateway@sha256:<digest>
```

A pull-request run may still record a build digest in the summary and artifact, but that digest is not on GHCR and must not be used to pull.

## Rollback

Revert this PR (or the merge commit on `main`). A pushed image does no harm on its own: nothing deploys it. Cluster apply on Alamo is a separate, later step and is not triggered by this workflow.
