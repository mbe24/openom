-- Rename the object-store key column from the R2-specific `r2_key` to the backend-neutral
-- `object_key`. The server speaks the S3 API to both MinIO (dev) and Cloudflare R2 (prod), so this
-- column names an object-store key, not an R2 concept. Renamed in place across the three tables that
-- carry it; RENAME COLUMN preserves existing data and any pointers already stored.
ALTER TABLE trees      RENAME COLUMN r2_key TO object_key;
ALTER TABLE tree_log   RENAME COLUMN r2_key TO object_key;
ALTER TABLE tree_blobs RENAME COLUMN r2_key TO object_key;
