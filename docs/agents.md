# AI coding agents

AI agents happily paste API keys into code and shell commands. leakscan can stop that before it happens.

## Claude Code hook

Add this to `.claude/settings.json` (per project) or `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Write|Edit|MultiEdit|Bash",
        "hooks": [{"type": "command", "command": "leakscan hook --agent claude-code"}]
      }
    ]
  }
}
```

`leakscan hook` reads the tool call from stdin and scans every string in it (file contents, edits, commands). If it
finds a HIGH or CRITICAL secret, it exits with code 2. Claude Code then blocks the call and shows the agent a redacted
reason, so it can rewrite the code to read from an environment variable. Use `--fail-on MEDIUM` to be stricter.

## Cursor hook

In `.cursor/hooks.json`:

```json
{
  "version": 1,
  "hooks": {
    "beforeShellExecution": [{"command": "leakscan hook --agent cursor"}],
    "beforeMCPExecution": [{"command": "leakscan hook --agent cursor"}]
  }
}
```

With `--agent cursor`, leakscan answers in Cursor's JSON format (`{"permission": "deny", ...}`).

## MCP server

`leakscan mcp` speaks the Model Context Protocol over stdio and exposes three tools: `scan_text`, `scan_path` and
`scan_staged`. Results are always redacted, so the agent never gets a full secret back.

```bash
claude mcp add leakscan -- leakscan mcp
```

Any other MCP client uses the same command, `leakscan mcp`.

## Any other agent

`leakscan hook --agent generic` exits 1 when it finds something. For a plain check without hooks, use
`leakscan scan --text "$CONTENT"` or `leakscan scan - < file`.
