from passlib.context import CryptContext
from sqlalchemy.orm import Session
from models import UsuarioBase, UsuarioCreate
from database import SessionLocal, Usuario
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from models import UsuarioResponse
from sqlalchemy.orm import Session
from database import Usuario
import os
import hashlib

# Crear un contexto de passlib para el hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Función para hash de contraseña
def hash_password(password: str):
    return pwd_context.hash(password)

# Función para verificar el hash de la contraseña
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# Función para generar las llaves ED25519
def generate_ed25519_keys():
    # Generar el par de llaves
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Serializar las llaves a formato adecuado para ED25519
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,  # Usar PKCS8 para clave privada
        encryption_algorithm=serialization.NoEncryption()  # Sin encriptación
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo  # Formato correcto para clave pública
    )

    return private_pem, public_pem

# Función para guardar la clave pública en la base de datos y la clave privada en un archivo
def save_keys_to_db_and_file(db, user_id, private_key_pem, public_key_pem):
    # Guardar la clave pública en la base de datos
    user = db.query(Usuario).filter(Usuario.id == user_id).first()
    user.public_key = public_key_pem.decode('utf-8')
    db.commit()

    # Guardar la clave privada en un archivo
    private_key_path = f"private_key_user_{user_id}.pem"
    with open(private_key_path, "wb") as private_file:
        private_file.write(private_key_pem)

    return private_key_path  # Devolver la ruta del archivo para que el médico lo descargue

# Función de registro de usuario
def create_user(db: Session, user: UsuarioCreate):
    hashed_password = hash_password(user.password)
    db_user = Usuario(username=user.username, password_hash=hashed_password, tipo_usuario=user.tipo_usuario)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    
    # Devuelve un UsuarioResponse, excluyendo el password y formateando los campos correctos
    return UsuarioResponse(
        id=db_user.id,
        username=db_user.username,
        tipo_usuario=db_user.tipo_usuario,
        fecha_creacion=db_user.fecha_creacion.strftime("%Y-%m-%d %H:%M:%S")  # Formateamos la fecha
    )

def authenticate_user(db: Session, username: str, password: str):
    db_user = db.query(Usuario).filter(Usuario.username == username).first()
    if db_user is None:
        return False
    if not verify_password(password, db_user.password_hash):
        return False

    # Verificar si las llaves ya han sido generadas
    if not db_user.llavesgeneradas:
        # Generar las llaves ED25519
        private_key_pem, public_key_pem = generate_ed25519_keys()

        # Guardar la clave pública en la base de datos y la privada en un archivo
        private_key_path = save_keys_to_db_and_file(db, db_user.id, private_key_pem, public_key_pem)

        # Actualizar la columna 'llavesgeneradas' a True (1)
        db_user.llavesgeneradas = True
        db.commit()

        # Devolver la respuesta con la ruta para descargar la clave privada
        return {
            "id": db_user.id,
            "username": db_user.username,
            "private_key_download_url": private_key_path  # Ruta para descargar la clave privada
        }

    # Si las llaves ya fueron generadas, solo devolvemos los datos del usuario
    return {
        "id": db_user.id,
        "username": db_user.username,
    }





