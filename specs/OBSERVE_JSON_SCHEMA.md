# Observe JSON Schema

Purpose: Stable schema for `sccgub observe --json` output.

```
{
  "height": 42,
  "finalized_height": 40,
  "mempool": 12,
  "slashing_events": 1,
  "api_sync_events": 25
}
```

Field semantics:
- `height`: current chain height (u64)
- `finalized_height`: last finalized height (u64)
- `mempool`: pending transactions count (u64)
- `slashing_events`: total slashing events (u64)
- `api_sync_events`: total API sync events (u64)
