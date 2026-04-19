# Plugin Development Guide

**Updated**: April 20, 2026  
**Audience**: Contributors and Integrators

## Overview

PwnPilot supports manifest-driven tool registration with strict validation and trust controls.

## Manifest Essentials

A plugin manifest should define:
- tool identity (`tool_name`, `version`)
- capabilities (including technique tags)
- invocation strategy (`adapter_type`, command template, timeout)
- parser strategy (`parser_type`)
- target matching constraints

## Runtime Flow

1. `manifest_loader` discovers manifests
2. schema + capability validation runs
3. trusted plugins are registered
4. planner capability requests are matched to registered tools
5. parser strategy resolves output normalization

## Generic CLI Adapter

Use generic CLI path when a tool supports deterministic command templates and parseable output.

## Trust Model

- Plugin signatures are validated against trusted keys.
- Untrusted or invalid signatures fail closed.

## Related Documents

- [ARCHITECTURE.md](ARCHITECTURE.md)
- [README.md](README.md)
