---
name: docs-generate-from-code
version: 1.3.0
description: Generate feature documentation from an existing codebase directory or feature path.
---

# docs-generate-from-code

Analyze an existing code directory or feature path and generate the corresponding feature documentation in `docs/<feature-slug>/` if it does not already exist. This skill is useful for backfilling documentation for legacy features that were implemented before the docs-driven workflow was adopted.

## Input

- A code directory path (e.g., `server/api/modules/products`, `client/dashboard/app/routes/products`) **or**
- A feature ID (e.g., `products-store`).

If the input is ambiguous, ask the user to confirm the target feature name and directory.

## Steps

1. **Load configuration**

   Read the `config.docs` object in `.docd.json` to resolve `root`, `specFile`, `guideFile`, `uiFile`, `changelogFile`, `changesDir`, `archiveDir`, `changeFilenamePattern`, `defaultStatus`, and `allowedStatuses`. A `null` value for `specFile`, `guideFile`, or `uiFile` means the file is disabled: never create, read, update, or link to it.

2. **Identify the target**

   - If the input is a directory path, derive a feature slug from it. Example: `server/api/modules/products` → `products` or `products-store`.
   - If the input is a feature ID, find the related code directory by scanning the subprojects (`server/api`, `client/dashboard`, `client/chatbox`, `client/fluxos`, `server/chatbots`, etc.).
   - Propose the derived feature slug to the user and ask for confirmation before proceeding.

3. **Check for existing docs**

   - If `docs/<feature-slug>/<guideFile>` already exists, report that documentation already exists and stop.
   - If only partial documentation exists, report what is missing and ask whether to generate the missing files or stop.

4. **Analyze the code**

   - List the directory structure.
   - Read key files (controllers, models, routes, components, services, templates) to understand the feature.
   - Use `grep` and `semantic_search` to find relevant API endpoints, data structures, and UI components.
   - Look for existing tests, migrations, or configuration files that reveal behavior.
   - Do not modify code; only read and summarize.

5. **Generate the feature docs**

   Create the following files with content derived from the code analysis (skip any file disabled (`null`) in the config):

   - `docs/<feature-slug>/<guideFile>`: description, how to use, goals, affected areas, tags, and links.
   - `docs/<feature-slug>/<specFile>`: architecture, API contracts, routes/endpoints, flows, and design decisions inferred from the code.
   - `docs/<feature-slug>/<uiFile>` (optional): visual details, colors, formats, typography, and placeholders for design URLs.
   - `docs/<feature-slug>/<changelogFile>`: empty table with Date, Change, Description, Responsible columns.
   - `docs/<feature-slug>/<changesDir>/`: empty directory for future change plans.

   For `guide.md`, include YAML frontmatter: `id`, `title`, `status`, `created_at`, `updated_at`, `owner`, `affected_areas`, `tags`.

6. **Present the generated docs**

   - Show a summary of what was analyzed.
   - List the generated files and their paths.
   - Highlight inferred decisions, assumptions, and anything that could not be determined from the code.
   - Ask the user to review and refine the generated docs.

7. **After user confirmation**

   - Save the generated files.
   - Recommend running `/docs-plan` when the user is ready to propose changes to this feature.

## Output

- List of generated documentation files.
- Summary of what was inferred from the code.
- List of assumptions or uncertain items that need human review.
- Recommendation to refine the docs manually or start a `/docs-plan` for the next change.

## Guardrails

- Do not overwrite existing documentation files unless explicitly instructed.
- Do not modify code or non-docs files.
- Do not generate implementation plans or change plans; this skill only creates feature documentation.
- Be explicit about assumptions; do not invent behaviors that are not supported by the code.
- If the codebase is too large to analyze exhaustively, focus on the entry points and public APIs, and note what was skipped.
- Always use the configured paths from `config.docs` in `.docd.json`.
- If the target directory is outside the workspace or in an ignored directory, stop and ask the user.
