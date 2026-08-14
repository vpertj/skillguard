ALTER TABLE audits DROP COLUMN IF EXISTS llm_results;
ALTER TABLE users DROP COLUMN IF EXISTS quota_llm_reviews;
