# Legal Holds Guide

**Updated**: April 20, 2026  
**Audience**: Compliance, Legal, Security Operations

## Purpose

Legal holds prevent retention TTL jobs from deleting engagement evidence while a hold is active.

## Lifecycle

1. `place_hold` -> active state
2. Active hold blocks TTL deletion
3. `release_hold` -> released state
4. Released record remains for audit history

## Core Rules

- One hold per engagement (`engagement_id` unique)
- Active hold: `released_at IS NULL`
- Released hold: `released_at IS NOT NULL` and `released_by IS NOT NULL`
- Hold records are retained as immutable compliance artifacts

## Operational Commands

### List active holds

```bash
sqlite3 /var/lib/pwnpilot/pwnpilot.db \
  "SELECT engagement_id, holder, reason, placed_at FROM legal_holds WHERE released_at IS NULL;"
```

### Release verification

```bash
sqlite3 /var/lib/pwnpilot/pwnpilot.db \
  "SELECT engagement_id, released_by, released_at FROM legal_holds WHERE released_at IS NOT NULL ORDER BY released_at DESC LIMIT 20;"
```

## Compliance Notes

- Hold placement and release must be audit logged.
- Evidence deletion jobs must check active hold state before deletion.
- Hold reason and actor identity should be preserved for external audits.

## Related Documents

- [roe-compliance.md](roe-compliance.md)
- [DB_OPERATIONS.md](DB_OPERATIONS.md)
- [CURRENT_SCHEMA.md](CURRENT_SCHEMA.md)
