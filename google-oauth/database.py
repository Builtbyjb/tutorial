from fastapi import Depends
from typing import Annotated, Optional
from sqlmodel import Field, Session, SQLModel, create_engine


class User(SQLModel, table=True):
  id: int = Field(primary_key=True)
  name: str = Field(index=True)
  access_token: str
  refresh_token: str | None = Field(default=None)


class TokenUpdate(SQLModel):
  access_token: str
  refresh_token: str | None = None


sqlite_file_name = "database.db"
sqlite_url = f"sqlite:///{sqlite_file_name}"

connect_args = {"check_same_thread": False}
engine = create_engine(sqlite_url, connect_args=connect_args)


def create_db_and_tables() -> None: SQLModel.metadata.create_all(engine)


def get_session():
  with Session(engine) as session:
    yield session


DB = Annotated[Session, Depends(get_session)]


class MemCache:
  def __init__(self) -> None:
    self.cache = dict()

  def get(self, session_id: str) -> Optional[str]:
    return self.cache[session_id]

  def set(self, session_id: str, user_id: str) -> bool:
    try: self.cache[session_id] = user_id
    except Exception as e:
      print(e)
      return False
    return True
    

CACHE = MemCache()