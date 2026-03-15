-- Add bit_index column to policies table for bitmap-based O(1) policy lookup
ALTER TABLE policies ADD COLUMN bit_index INTEGER;

-- Assign sequential bit indexes to existing active policies per tenant
WITH ranked AS (
    SELECT id, tenant_id,
           ROW_NUMBER() OVER (PARTITION BY tenant_id ORDER BY priority, created_at) - 1 AS idx
    FROM policies
    WHERE active = true
)
UPDATE policies p
SET bit_index = r.idx
FROM ranked r
WHERE p.id = r.id;
