from pydantic import BaseModel, json
from typing import Optional
from sqlalchemy import TypeDecorator, Unicode


class NewScan(BaseModel):
    name: str
    type: str
    target: str
    status: str
    result: Optional[str] = None


class Scan(NewScan):
    id: int


class ScanTarget(BaseModel):
    url: str
    type: str


class ScanId(BaseModel):
    ok: bool = True
    scan_id: int


class JSONType(TypeDecorator):
    impl = Unicode

    def process_bind_param(self, value, dialect):
        if value is not None:
            value = json.dumps(value)
        return value

    def process_result_value(self, value, dialect):
        if value is not None:
            value = json.loads(value)
        return value
