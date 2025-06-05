from pydantic import BaseModel
from datetime import datetime

class UsuarioBase(BaseModel):
    username: str

class UsuarioCreate(UsuarioBase):
    password: str
    tipo_usuario: str

class UsuarioResponse(UsuarioBase):
    id: int
    tipo_usuario: str
    fecha_creacion: str  # Asegúrate de que sea un string en el formato adecuado

    class Config:
        orm_mode = True  # Esto permite que FastAPI pueda convertir el modelo de SQLAlchemy a Pydantic
