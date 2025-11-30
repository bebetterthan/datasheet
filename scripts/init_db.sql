-- Initialize PostgreSQL database for Security Dataset Scraper
-- This script runs automatically when using docker-compose with postgres profile

-- Create extension for full text search
CREATE EXTENSION
IF NOT EXISTS pg_trgm;
CREATE EXTENSION
IF NOT EXISTS unaccent;

-- Scraped URLs table
CREATE TABLE
IF NOT EXISTS scraped_urls
(
    id SERIAL PRIMARY KEY,
    url TEXT NOT NULL UNIQUE,
    url_hash VARCHAR
(64) NOT NULL,
    source VARCHAR
(100) NOT NULL,
    status VARCHAR
(20) NOT NULL DEFAULT 'pending',
    scraped_at TIMESTAMP
WITH TIME ZONE,
    error_message TEXT,
    retry_count INTEGER DEFAULT 0,
    response_code INTEGER,
    content_hash VARCHAR
(64),
    created_at TIMESTAMP
WITH TIME ZONE DEFAULT NOW
(),
    updated_at TIMESTAMP
WITH TIME ZONE DEFAULT NOW
()
);

-- Create index for faster lookups
CREATE INDEX
IF NOT EXISTS idx_scraped_urls_source ON scraped_urls
(source);
CREATE INDEX
IF NOT EXISTS idx_scraped_urls_status ON scraped_urls
(status);
CREATE INDEX
IF NOT EXISTS idx_scraped_urls_url_hash ON scraped_urls
(url_hash);

-- Raw content table
CREATE TABLE
IF NOT EXISTS raw_content
(
    id SERIAL PRIMARY KEY,
    url_id INTEGER REFERENCES scraped_urls
(id) ON
DELETE CASCADE,
    title TEXT,
    content TEXT
NOT NULL,
    html_content TEXT,
    content_hash VARCHAR
(64) NOT NULL,
    word_count INTEGER,
    created_at TIMESTAMP
WITH TIME ZONE DEFAULT NOW
()
);

CREATE INDEX
IF NOT EXISTS idx_raw_content_url_id ON raw_content
(url_id);
CREATE INDEX
IF NOT EXISTS idx_raw_content_hash ON raw_content
(content_hash);

-- Processed samples table (Alpaca format ready)
CREATE TABLE
IF NOT EXISTS processed_samples
(
    id SERIAL PRIMARY KEY,
    source_url_id INTEGER REFERENCES scraped_urls
(id) ON
DELETE
SET NULL
,
    instruction TEXT NOT NULL,
    input TEXT DEFAULT '',
    output TEXT NOT NULL,
    category VARCHAR
(100),
    subcategory VARCHAR
(100),
    difficulty VARCHAR
(20) DEFAULT 'intermediate',
    tags TEXT[], -- PostgreSQL array for tags
    token_count INTEGER,
    quality_score FLOAT,
    is_duplicate BOOLEAN DEFAULT FALSE,
    duplicate_of INTEGER REFERENCES processed_samples
(id),
    created_at TIMESTAMP
WITH TIME ZONE DEFAULT NOW
(),
    updated_at TIMESTAMP
WITH TIME ZONE DEFAULT NOW
()
);

CREATE INDEX
IF NOT EXISTS idx_processed_samples_category ON processed_samples
(category);
CREATE INDEX
IF NOT EXISTS idx_processed_samples_difficulty ON processed_samples
(difficulty);
CREATE INDEX
IF NOT EXISTS idx_processed_samples_duplicate ON processed_samples
(is_duplicate);

-- Full text search index
CREATE INDEX
IF NOT EXISTS idx_processed_samples_fts ON processed_samples 
    USING GIN
(to_tsvector
('english', instruction || ' ' || output));

-- Code blocks table
CREATE TABLE
IF NOT EXISTS code_blocks
(
    id SERIAL PRIMARY KEY,
    content_id INTEGER REFERENCES raw_content
(id) ON
DELETE CASCADE,
    code TEXT
NOT NULL,
    language VARCHAR
(50),
    line_count INTEGER,
    created_at TIMESTAMP
WITH TIME ZONE DEFAULT NOW
()
);

CREATE INDEX
IF NOT EXISTS idx_code_blocks_language ON code_blocks
(language);

-- Scrape sessions table
CREATE TABLE
IF NOT EXISTS scrape_sessions
(
    id SERIAL PRIMARY KEY,
    source VARCHAR
(100) NOT NULL,
    started_at TIMESTAMP
WITH TIME ZONE NOT NULL,
    completed_at TIMESTAMP
WITH TIME ZONE,
    total_urls INTEGER DEFAULT 0,
    success_count INTEGER DEFAULT 0,
    error_count INTEGER DEFAULT 0,
    skipped_count INTEGER DEFAULT 0,
    status VARCHAR
(20) DEFAULT 'running',
    config JSONB
);

-- Dataset exports table
CREATE TABLE
IF NOT EXISTS dataset_exports
(
    id SERIAL PRIMARY KEY,
    export_format VARCHAR
(50) NOT NULL,
    file_path TEXT NOT NULL,
    sample_count INTEGER NOT NULL,
    file_size_bytes BIGINT,
    config JSONB,
    created_at TIMESTAMP
WITH TIME ZONE DEFAULT NOW
()
);

-- Analytics view
CREATE OR REPLACE VIEW dataset_analytics AS
SELECT
    category,
    COUNT(*) as sample_count,
    AVG(token_count) as avg_tokens,
    MIN(token_count) as min_tokens,
    MAX(token_count) as max_tokens,
    AVG(quality_score) as avg_quality,
    COUNT(*) FILTER
(WHERE difficulty = 'beginner') as beginner_count,
    COUNT
(*) FILTER
(WHERE difficulty = 'intermediate') as intermediate_count,
    COUNT
(*) FILTER
(WHERE difficulty = 'advanced') as advanced_count
FROM processed_samples
WHERE is_duplicate = FALSE
GROUP BY category
ORDER BY sample_count DESC;

-- Function to update timestamps
CREATE OR REPLACE FUNCTION update_updated_at
()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW
();
RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Triggers for auto-updating timestamps
CREATE TRIGGER trigger_scraped_urls_updated
    BEFORE
UPDATE ON scraped_urls
    FOR EACH ROW
EXECUTE FUNCTION update_updated_at
();

CREATE TRIGGER trigger_processed_samples_updated
    BEFORE
UPDATE ON processed_samples
    FOR EACH ROW
EXECUTE FUNCTION update_updated_at
();

-- Sample data cleanup function
CREATE OR REPLACE FUNCTION cleanup_old_errors
(days_old INTEGER DEFAULT 30)
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM scraped_urls
    WHERE status = 'error'
        AND created_at < NOW() - (days_old || ' days')
    ::INTERVAL;

GET DIAGNOSTICS deleted_count = ROW_COUNT;
RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Grant permissions
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO scraper;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO scraper;
