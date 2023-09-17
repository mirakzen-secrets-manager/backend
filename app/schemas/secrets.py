from typing import Dict, Optional

from pydantic import BaseModel


class NewSecret(BaseModel):
    name: str
    data: Dict


class UpdatedSecret(BaseModel):
    name: Optional[str] = None
    data: Optional[Dict] = None
