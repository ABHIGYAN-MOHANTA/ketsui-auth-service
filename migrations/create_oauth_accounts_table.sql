-- Create oauth_accounts table
CREATE TABLE IF NOT EXISTS oauth_accounts (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    provider VARCHAR(50) NOT NULL,
    email VARCHAR(255),
    name VARCHAR(255),
    first_name VARCHAR(255),
    last_name VARCHAR(255),
    nickname VARCHAR(255),
    description TEXT,
    avatar_url TEXT,
    location VARCHAR(255),
    access_token TEXT,
    access_token_secret TEXT,
    refresh_token TEXT,
    expires_at TIMESTAMP WITH TIME ZONE,
    id_token TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    
    -- Create a unique constraint on user_id and provider
    UNIQUE(user_id, provider)
);

-- Create indexes for common lookups
CREATE INDEX IF NOT EXISTS idx_oauth_accounts_email ON oauth_accounts(email);
CREATE INDEX IF NOT EXISTS idx_oauth_accounts_provider ON oauth_accounts(provider); 