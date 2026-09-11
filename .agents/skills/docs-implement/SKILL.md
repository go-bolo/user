---
name: docs-implement
version: 1.3.0
description: Implement tasks from an approved change plan using subagents or Agent Manager for parallel execution.
---

# docs-implement

Implement the tasks defined in an approved change plan located in `docs/<feature-id>/<changesDir>/`. Use subagents or Agent Manager to distribute independent tasks and execute them in parallel whenever possible.

## Input

- Feature ID and change ID (e.g., `/docs-implement products-store/ui-mobile-de-produtos-para-clientes`).

## Steps

1. **Load configuration**

   Read the `config.docs` object in `.docd.json` to resolve `root`, `specFile`, `guideFile`, `uiFile`, `changelogFile`, `changesDir`, `archiveDir`, and `allowedStatuses`. A `null` value for `specFile`, `guideFile`, or `uiFile` means the file is disabled: never create, read, update, or link to it.

2. **Read the plan**

   - Read `docs/<feature-id>/<guideFile>` for context (if enabled).
   - Read `docs/<feature-id>/<specFile>` for architecture and contracts (if enabled).
   - Read `docs/<feature-id>/<changesDir>/<date>-<change-id>-plan.md` for the task list.

3. **Confirm approval**

   - Ensure the plan status is `pending` or `in_progress`. If it is `completed` or `archived`, report that and stop.
   - If the plan was not explicitly approved by the user in a previous `/docs-plan` step, pause and ask for confirmation before proceeding.

4. **Group tasks by affected area**

   - For each unchecked task (`- [ ]`), determine the affected area based on the task description and the `affected_areas` metadata from the guide.
   - Group independent tasks that can run in parallel.
   - Identify dependencies between tasks (e.g., backend endpoint must exist before frontend integration). Dependent tasks must run sequentially.

5. **Distribute tasks**

   - Use **subagents** (`task` tool) or **Agent Manager** to delegate tasks to the appropriate specialized agents:
     - `programador-senior` for any subproject implementation.
     - `arquiteto` for cross-service design decisions.
     - `designer` for UI/UX changes.
     - `devops` for infrastructure or CI/CD changes.
   - When delegating, pass:
     - The exact task description.
     - Relevant sections from the plan, spec, and ui docs (whichever are enabled).
     - The affected area and file paths if known.
     - A clear instruction to mark the task as complete in the plan file after finishing.

6. **Execute in parallel**

   - Launch independent subagents/Agent Manager sessions in parallel to reduce total time and avoid overloading a single agent's context.
   - Wait for all parallel tasks to finish before proceeding to dependent tasks.

7. **Mark tasks complete**

   - As each task finishes, update the plan file: `- [ ]` → `- [x]`.
   - Update `updated_at` and `status` (to `in_progress`) in the frontmatter while working.

8. **Finish**

   - If all tasks are complete, set `status` to `completed` and update `updated_at`.
   - Report progress and any files modified.
   - **Recommend running `/docs-sync <feature-id>/<change-id>` to finalize the plan and update the changelog and feature docs.**

## Output

Report the current progress: "X/Y tasks complete" and list completed/pending tasks. If subagents were used, summarize which agents handled which tasks.

## Guardrails

- Do not skip tasks.
- Do not implement a plan that was not explicitly approved.
- If a task is unclear, pause and ask for clarification before implementing.
- If a task reveals a design issue, suggest updating the spec or change plan.
- Do not modify files outside the scope of the plan unless explicitly required by the task.
- Always update the change plan after completing a task.
- Prefer parallel execution for independent tasks; respect dependencies for sequential tasks.
- Use Agent Manager when multiple distinct areas are affected and worktree isolation is beneficial.
