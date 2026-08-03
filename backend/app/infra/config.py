from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    PROJECT_NAME: str = "CyberShield-AI-SOC"
    ENV: str = "development"
    DEBUG: bool = True

    # Backend Server Configuration
    BACKEND_HOST: str = "0.0.0.0"
    BACKEND_PORT: int = 8000
    SECRET_KEY: str = "replace-this-with-a-very-secure-random-secret-key-for-jwt-tokens"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # Database Configuration
    POSTGRES_USER: str = "postgres"
    POSTGRES_PASSWORD: str = "postgres_secure_password_123"
    POSTGRES_DB: str = "cybershield_db"
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432

    @property
    def database_url(self) -> str:
        return f"postgresql://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"

    # Redis Configurations
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_PASSWORD: str = "redis_secure_password_456"

    # AI Configurations
    PHISHING_MODEL_PATH: str = "models/phishing_detector_v1"
    SPAM_MODEL_PATH: str = "models/spam_classifier_v1"
    CONFIDENCE_THRESHOLD: float = 0.82

    # Third Party Feeds
    VIRUSTOTAL_API_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""
    SHODAN_API_KEY: str = ""
    OTX_API_KEY: str = ""
    URLHAUS_API_KEY: str = ""
    OPENPHISH_API_KEY: str = ""
    THREAT_INTEL_CACHE_TTL: int = 86400

    # ClamAV Configuration
    CLAMAV_HOST: str = "localhost"
    CLAMAV_PORT: int = 3310

    # IMAP Configuration
    MAIL_INBOX_IMAP_SERVER: str = ""
    MAIL_INBOX_USER: str = ""
    MAIL_INBOX_PASSWORD: str = ""
    MAIL_INBOX_PORT: int = 993

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

settings = Settings()
