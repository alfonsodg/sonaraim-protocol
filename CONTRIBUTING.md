# Contributing to Sonaraim Protocol

Thank you for your interest in contributing to `sonaraim-protocol`! This repository defines the formal wire specifications, Sealed Sender envelopes, and declarative Sonaraim Card validators for the Sonaraim ecosystem.

To maintain cryptographic rigor, code quality, and security invariants, all contributors must adhere to the following engineering standards.

---

## 1. Branching & Git Workflow

- **`develop` Branch**: The primary integration branch. All feature and bugfix branches must branch from and merge into `develop`.
- **`main` Branch**: Reserved exclusively for production-ready, release-tagged code (`vMAJOR.MINOR.PATCH`). Never merge directly to `main`.
- **Feature Branches**: Name new features `feature/<short-description>` (e.g., `feature/mls-tree-ratchet`).
- **Bugfix Branches**: Name bug fixes `fix/<short-description>` (e.g., `fix/replay-window-boundary`).
- **Pull Requests**: Open Pull Requests targeting `develop`. Every PR must pass all CI/CD quality gates before merge review.

---

## 2. Test-Driven Development (TDD) Mandatory

`sonaraim-protocol` enforces strict Test-Driven Development (TDD):

1. **Red**: Write a failing unit or integration test reproducing the bug or specifying the new protocol capability before touching implementation code.
2. **Green**: Implement the minimal, clean code required to pass the test.
3. **Refactor**: Clean up the implementation while keeping all tests passing.
4. **No Uncovered Code**: Never commit production code without corresponding test assertions covering edge cases, invalid inputs, and boundary conditions.

---

## 3. Code Quality & Modularity Standards

- **File Length Limit**: Every source file must remain under 300 lines. Break larger modules into focused single-responsibility files.
- **Mandatory Documentation**: Every public struct, enum, trait, function, and method must include Rustdoc comments (`///`) detailing parameters, return values, and failure modes. Complex logic blocks must include inline comments explaining *why* (not just *what*).
- **Zero Hardcoding**: Never embed magic numbers, fixed timeouts, cryptographic secrets, or default URLs in source code. All configuration must be provided via explicit arguments or validated data structures.
- **Error Handling**: Never panic (`unwrap()`, `expect()`) in production code paths. Use typed errors (`Result<T, ProtocolError>`) with descriptive variants.

---

## 4. Conventional Commits

All commit messages must follow the Conventional Commits specification and reference an issue number:

```text
<type>(<scope>): <subject> (Ref #N)
```

- **Types**: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `perf`.
- **Scope**: Component being modified (`envelope`, `card`, `crypto`, `keyring`, `mls`, `wire`, `replay`).
- **Subject**: Imperative, present tense, lowercase (e.g., `add replay window sliding eviction`).
- **Issue Reference**: Always reference the tracked issue with `Ref #N` (never `Closes #N`, as issues undergo manual verification before closing).

Example:

```text
feat(envelope): enforce 32-byte ephemeral x25519 public key invariant (Ref #16)
```

---

## 5. Tooling, Verification & Quality Gates

Before submitting changes, run and verify the following commands locally:

```bash
# 1. Format verification
cargo fmt --check

# 2. Static analysis and linter checks
cargo clippy --all-targets -- -D warnings

# 3. Complete test suite execution
cargo test

# 4. Markdown quality and linting verification
npx --yes markdownlint-cli2 "*.md" "docs/*.md"
```

All 4 commands must pass with zero errors and zero warnings.

---

## 6. Documentation & Architecture Standards

- **English Only**: All code, comments, documentation, commit messages, and PR descriptions must be written in English.
- **Mermaid Diagrams**: Mermaid diagrams belong **exclusively** inside `docs/DIAGRAMS.md`. Never embed ```` ```mermaid ```` blocks in `README.md`, `ARCHITECTURE.md`, or other markdown files (use text or ASCII art instead).
- **Markdown Linting**: All markdown documents must pass `markdownlint` without warnings.
