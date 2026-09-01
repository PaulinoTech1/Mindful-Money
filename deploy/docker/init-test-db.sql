-- Dev/test-only. Creates the second database used by test_demo.py's
-- ServerCase fixture, alongside the primary vault_dev database that
-- POSTGRES_DB already creates. Not used in production.
CREATE DATABASE vault_test OWNER vault;
