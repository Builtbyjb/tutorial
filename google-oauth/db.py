from typing import Annotated
from sqlmodel import Field, Session, SQLModel, create_engine


class User(SQLModel, table=True):
  id: int = Field(primary_key=True)
  name: str = Field(index=True)
  access_token: str
  refresh_token: str | None = Field(default=None)


sqlite_file_name = "database.db"
sqlite_url = f"sqlite:///{sqlite_file_name}"

connect_args = {"check_same_thread": False}
engine = create_engine(sqlite_url, connect_args=connect_args)


def create_db_and_tables(): SQLModel.metadata.create_all(engine)


def get_session():
  with Session(engine) as session:
    yield session