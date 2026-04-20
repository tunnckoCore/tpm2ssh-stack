# develop loop/cycle

- read progress to get what's left to be done
- spawn 5 minion subagents (always, AND ALL, in openai-codex gpt-5.4 on high thinking) with their own job and own `git worktree` for the task.
- git worktrees should be on `~/code/tpm2ssh-stack-worktrees/` - no suffixes or etc.
- when agents are done, they should commit
- you should then start merging into `~/code/tpm2ssh-stack/` and `master` branch. resolve conflicts if such.
- after each agent's job successfull merge, run Cargo build and test, if all is fine -> push to remote master.
- then continue with other merge, then push to remote master.
- after all is done, write progress on `docs/progress.md` with what's done and what's left to be done in the grand schema of things of the project. the plan is in `docs/*_PLAN.md`
