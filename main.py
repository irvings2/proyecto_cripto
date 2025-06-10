from fastapi import FastAPI, Depends, HTTPException, File, UploadFile
from sqlalchemy import create_engine, Column, Integer, String, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy import select
from pydantic import BaseModel
from passlib.context import CryptContext
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from io import BytesIO
from fastapi.responses import FileResponse
import os

DATABASE_URL = "postgresql://postgres.gijqjegotyhtdbngcuth:nedtu3-ruqvec-mixSew@aws-0-us-east-2.pooler.supabase.com:6543/postgres"

# Crear la base y el motor de SQLAlchemy
engine = create_engine(DATABASE_URL, pool_size=10, max_overflow=20)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Declarative Base para las tablas
Base = declarative_base()

class Usuario(Base):
    __tablename__ = 'usuario'  # Nombre de tu tabla
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, index=False)
    password_hash = Column(String, index=False)
    tipo_usuario = Column(String, index=False)
    llavesgeneradas = Column(Boolean, default=False)
    public_key = Column(String, nullable=True)

app = FastAPI()

# Dependencia para obtener la sesión de base de datos
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
        
# Pydantic model para la validación de datos del nuevo usuario
class UsuarioCreate(BaseModel):
    username: str
    password: str
    tipo_usuario: str

    class Config:
        orm_mode = True

# Configuración de passlib para el hash de la contraseña
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Función para generar el hash de la contraseña
def hash_password(password: str):
    return pwd_context.hash(password)

@app.get("/usuarios/")
async def get_usuarios(db: Session = Depends(get_db)):
    # Realizar el SELECT en la tabla de usuarios
    query = select(Usuario)
    result = db.execute(query).scalars().all()  # Obtener todos los usuarios
    return {"usuarios": result}

@app.post("/usuarios/")
async def create_usuario(usuario: UsuarioCreate, db: Session = Depends(get_db)):
    # Verificar si el username ya existe
    existing_user = db.query(Usuario).filter(Usuario.username == usuario.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="El nombre de usuario ya está registrado.")

    # Crear una nueva instancia de Usuario y agregarla a la base de datos
    hashed_password = hash_password(usuario.password)  # Generar el hash de la contraseña
    new_user = Usuario(username=usuario.username, password_hash=hashed_password, tipo_usuario=usuario.tipo_usuario)
    db.add(new_user)
    db.commit()  # Guardar los cambios
    db.refresh(new_user)  # Refrescar la instancia para obtener el id generado

    return {"id": new_user.id, "username": new_user.username, "tipo_usuario": new_user.tipo_usuario}

@app.post("/login/")
async def login(username: str, password: str, db: Session = Depends(get_db)):
    user = db.query(Usuario).filter(Usuario.username == username).first()
    
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    
    # Verificar contraseña
    if not pwd_context.verify(password, user.password_hash):
        raise HTTPException(status_code=401, detail="Contraseña incorrecta")
    
    # Verificar si las llaves ya fueron generadas
    if user.llavesgeneradas:
        return {"message": "Inicio de sesión exitoso. Las llaves ya han sido generadas."}
    
    # Si no han sido generadas, creamos las llaves
    private_key, public_key = generate_ed25519_keys()
    
    # Guardar la clave pública en la base de datos
    user.public_key = public_key
    user.llavesgeneradas = True
    db.commit()

    # Guardar la clave privada como un archivo .pem para ser descargado
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    private_key_file_path = f"private_key_{username}.pem"
    
    # Guardar el archivo de la clave privada en el servidor para permitir la descarga
    with open(private_key_file_path, "wb") as f:
        f.write(private_key_pem)
    
    # Devolver el archivo de la clave privada para ser descargado
    return FileResponse(path=private_key_file_path, filename=private_key_file_path, media_type='application/pem')

@app.post("/firmar_mensaje/")
async def firmar_mensaje(username: str, mensaje: str, private_key_file: UploadFile = File(...), db: Session = Depends(get_db)):
    # Buscar el usuario en la base de datos
    user = db.query(Usuario).filter(Usuario.username == username).first()
    
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    
    # Verificar si las llaves están generadas
    if not user.llavesgeneradas:
        raise HTTPException(status_code=400, detail="Las llaves no han sido generadas para este usuario")
    
    # Cargar la clave privada desde el archivo PEM proporcionado por el usuario
    private_key_pem = await private_key_file.read()
    try:
        private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    except Exception as e:
        raise HTTPException(status_code=400, detail="No se pudo cargar la clave privada")

    # Firmar el mensaje usando la clave privada
    try:
        signature = private_key.sign(mensaje.encode())  # Firmar el mensaje con la clave privada
    except Exception as e:
        raise HTTPException(status_code=400, detail="Error al firmar el mensaje")
    
    # Retornar la firma
    return {
        "message": "Mensaje firmado con éxito.",
        "firma": signature.hex()  # Devolver la firma como un string hexadecimal
    }

# Función para generar las llaves ED25519
def generate_ed25519_keys():
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    # Serializar la clave pública a formato PEM
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    return private_key, public_key_pem
