from typing import Optional
from pydantic import BaseModel

class BlueprintFileLocation(BaseModel):
    name: str
    path: str

class IconConfiguration(BaseModel):
    blueprint_file_location: Optional[BlueprintFileLocation] = None
    url: Optional[str] = None