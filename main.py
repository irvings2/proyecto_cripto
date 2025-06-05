from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session
from models import UsuarioCreate, UsuarioResponse  # Asegúrate de importar correctamente los esquemas de Pydantic
from database import SessionLocal, create_db, Usuario
from auth import create_user, authenticate_user
from fastapi.responses import FileResponse
import os

app = FastAPI()

# Crear la base de datos si no existe
create_db()

# Dependencia para obtener la sesión de la base de datos
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Ruta para registrar un nuevo usuario
@app.post("/register/", response_model=UsuarioResponse)
def register(user: UsuarioCreate, db: Session = Depends(get_db)):
    # Verificar si el username ya existe
    db_user = db.query(Usuario).filter(Usuario.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already registered")
    
    # Crear usuario
    return create_user(db=db, user=user)

# Ruta para login de usuario
@app.post("/login/")
def login(user: UsuarioCreate, db: Session = Depends(get_db)):
    db_user = authenticate_user(db=db, username=user.username, password=user.password)
    if not db_user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    
    # Retornamos la respuesta del login (incluyendo la URL de la clave privada si es la primera vez)
    return db_user

@app.get("/download/private-key/{user_id}")
async def download_private_key(user_id: int):
    private_key_path = f"private_key_user_{user_id}.pem"
    
    # Verificamos si el archivo existe antes de devolverlo
    if os.path.exists(private_key_path):
        return FileResponse(private_key_path, media_type='application/octet-stream', filename=f"private_key_user_{user_id}.pem")
    else:
        raise HTTPException(status_code=404, detail="Private key file not found")
