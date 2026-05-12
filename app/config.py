from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    DATABASE_URL: str
    UPLOAD_DIR: str = "uploads"
    VIRUSTOTAL_API_KEY: str = ""

    class Config:
        env_file = ".env"

settings = Settings()