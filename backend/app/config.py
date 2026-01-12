from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str = "postgresql+psycopg2://secureops:secureops@localhost:5432/secureops"


settings = Settings()
