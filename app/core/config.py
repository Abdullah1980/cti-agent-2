from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv
from pydantic import Field
from pydantic_settings import BaseSettings


ROOT_DIR = Path(__file__).resolve().parents[2]
DATA_DIR = ROOT_DIR / "data"
ANALYSES_DIR = DATA_DIR / "analyses"
EXPORTS_DIR = DATA_DIR / "exports"
DB_PATH = DATA_DIR / "cti_agent2.db"

load_dotenv(ROOT_DIR / ".env")


class Settings(BaseSettings):
    app_name: str = Field(default="CTI Agent 2", alias="APP_NAME")
    openai_api_key: str | None = Field(default=None, alias="OPENAI_API_KEY")
    openai_model: str = Field(default="gpt-5.4-mini", alias="OPENAI_MODEL")
    virustotal_api_key: str | None = Field(default=None, alias="VIRUSTOTAL_API_KEY")
    malwarebazaar_api_key: str | None = Field(default=None, alias="MALWAREBAZAAR_API_KEY")
    abuseipdb_api_key: str | None = Field(default=None, alias="ABUSEIPDB_API_KEY")
    urlscan_api_key: str | None = Field(default=None, alias="URLSCAN_API_KEY")
    otx_api_key: str | None = Field(default=None, alias="OTX_API_KEY")
    request_timeout_seconds: int = Field(default=25, alias="REQUEST_TIMEOUT_SECONDS")

    class Config:
        populate_by_name = True
        extra = "ignore"


@lru_cache
def get_settings() -> Settings:
    ANALYSES_DIR.mkdir(parents=True, exist_ok=True)
    EXPORTS_DIR.mkdir(parents=True, exist_ok=True)
    return Settings()
