# Database Operations Guide

**Updated**: April 20, 2026  
**Audience**: DBAs, Operators, Platform Engineers

## Scope

This document covers database lifecycle and operational controls:
- Alembic migration procedures
- Persistent rate-limit and legal-hold tables
- Backup and restore runbooks
- Manual verification queries
- Cleanup and recovery workflows

For service install/start and systemd flows, use [DEPLOYMENT.md](DEPLOYMENT.md).

## Migration Operations

### Apply and verify

```bash
alembic upgrade head
alembic current
alembic history
```

### Create migrations

```bash
alembic revision -m "add_feature_table"
alembic revision --autogenerate -m "sync_models"
```

### Rollback

```bash
alembic downgrade -1
```

## Persistence Tables

### `rate_limit_records`

Purpose: Durable token-bucket events so `active_scan` limits survive restart/resume.

Key columns:
- `id` (pk)
- `engagement_id` (indexed)
- `action_class` (indexed)
- `timestamp` (indexed)

Operational checks:

```sql
SELECT action_class, COUNT(*)
FROM rate_limit_records
WHERE engagement_id = 'ENGAGEMENT-UUID'
  AND timestamp > (CAST(strftime('%s','now') AS FLOAT) - 60)
GROUP BY action_class;
```

### `legal_holds`

Purpose: Persist legal holds that block TTL deletion.

Key columns:
- `id` (pk)
- `engagement_id` (unique, indexed)
- `holder`
- `reason`
- `placed_at`
- `released_at`
- `released_by`

Operational checks:

```sql
SELECT engagement_id, holder, placed_at
FROM legal_holds
WHERE released_at IS NULL;
```

## Backup and Restore

### SQLite backup

```bash
sqlite3 /var/lib/pwnpilot/pwnpilot.db ".backup /var/backups/pwnpilot/pwnpilot-$(date +%F).db"
```

### Integrity check

```bash
sqlite3 /var/lib/pwnpilot/pwnpilot.db "PRAGMA integrity_check;"
```

### Restore

```bash
systemctl stop pwnpilot
cp /var/backups/pwnpilot/pwnpilot-YYYY-MM-DD.db /var/lib/pwnpilot/pwnpilot.db
systemctl start pwnpilot
```

## Recovery and Cleanup

### Orphaned rate-limit rows

```sql
DELETE FROM rate_limit_records
WHERE engagement_id NOT IN (SELECT engagement_id FROM engagements);
```

### Verify hold state consistency

```sql
SELECT id, engagement_id, released_at, released_by
FROM legal_holds
WHERE (released_at IS NULL AND released_by IS NOT NULL)
   OR (released_at IS NOT NULL AND released_by IS NULL);
```

## Related Documents

- [CURRENT_SCHEMA.md](CURRENT_SCHEMA.md)
- [LEGAL_HOLDS.md](LEGAL_HOLDS.md)
- [DEPLOYMENT.md](DEPLOYMENT.md)
