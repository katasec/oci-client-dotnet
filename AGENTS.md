# Delivery playbook

## Task completion and integration

Every completed task must be integrated into `main`, not left on a feature branch:

1. Work on a dedicated `codex/` branch; never commit implementation directly to `main`.
2. Run the task's required validation and record its actual result.
3. Commit and push the completed work, create a PR to `main`, and merge it once the required
   verification passes.
4. If a task changes more than one repository, repeat this process for every changed repository.
5. Finish on a clean worktree with no unpushed commits. Do not merge failing or unverified work.
