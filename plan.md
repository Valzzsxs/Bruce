1. The error is exactly: `HTTP 404: workflow .github/workflows/deploy.yml not found on the default branch`.
2. This is caused by a step in `.github/workflows/buil_parallel.yml` that attempts to run a workflow named `deploy.yml`, which doesn't exist in the default branch (or at all).
3. Let's inspect `.github/workflows/buil_parallel.yml`.
4. Line 234: `gh workflow run .github/workflows/deploy.yml --ref WebPage`
5. Since the repo doesn't seem to have `deploy.yml` (I ran `ls -la .github/workflows` earlier and it only had `PR_All_envs.yml`, `PR_check.yml`, `buil_parallel.yml`, `manual_build_sel_env.yml`), this step will always fail.
6. The user must have deleted or renamed `deploy.yml` or it was never merged to `main`.
7. I can fix this by wrapping the command in a `|| true` or removing the `gh workflow run .github/workflows/deploy.yml --ref WebPage` call. I will comment it out or remove it to fix the CI.
