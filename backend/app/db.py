from sqlmodel import SQLModel, create_engine, Session
from .config import settings
from . import models  # noqa: F401

engine = create_engine(settings.database_url, echo=False)


def init_db() -> None:
    SQLModel.metadata.create_all(engine)


def get_session():
    with Session(engine) as session:
        yield session
