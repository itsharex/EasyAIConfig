# Multi-agent demo note

This file is a minimal, documentation-only change for a safe multi-agent demo.

## Why this change is safe

- It does not modify runtime code.
- It does not affect build output.
- It is easy to review and easy to revert.

## Suggested demo split

- Agent 1: inspect repository status and avoid dirty files
- Agent 2: choose a safe target file for a tiny change
- Agent 3: verify the final diff only contains the doc addition
