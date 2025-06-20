from fastapi import FastAPI, Depends, HTTPException, File, UploadFile, Form
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, Boolean, ForeignKey, Text, TIMESTAMP
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from sqlalchemy import select
from pydantic import BaseModel
from passlib.context import CryptContext
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from io import BytesIO
from fastapi.responses import FileResponse
from typing import Union, Optional
from datetime import datetime
from tempfile import NamedTemporaryFile
import zipfile
from io import BytesIO
from fastapi.responses import StreamingResponse
import os

DATABASE_URL = "postgresql://postgres.gijqjegotyhtdbngcuth:nedtu3-ruqvec-mixSew@aws-0-us-east-2.pooler.supabase.com:6543/postgres"

# Crear la base y el motor de SQLAlchemy
engine = create_engine(DATABASE_URL, pool_size=10, max_overflow=20)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Ruta temporal para guardar los archivos
TEMP_DIR = "temp"

# Crear directorio si no existe
if not os.path.exists(TEMP_DIR):
    os.makedirs(TEMP_DIR)


# Declarative Base para las tablas
Base = declarative_base()

class Usuario(Base):
    __tablename__ = 'usuario'  # Nombre de tu tabla
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, index=False)
    password_hash = Column(String, index=False)
    tipo_usuario = Column(String, index=False)
    llavesgeneradas = Column(Boolean, default=False)
    public_key_ed = Column(String, nullable=True)
    public_key_x255 = Column(String, nullable=True)
    
    medico = relationship("Medico", back_populates="usuario", uselist=False)
    paciente = relationship("Paciente", back_populates="usuario", uselist=False)
    farmaceutico = relationship("Farmaceutico", back_populates="usuario", uselist=False)
    
class Medico(Base):
    __tablename__ = 'medico'

    id = Column(Integer, primary_key=True, index=True)
    usuario_id = Column(Integer, ForeignKey('usuario.id'))  # Relación con la tabla usuarios
    nombre = Column(String)
    apellido_paterno = Column(String)
    apellido_materno = Column(String)
    especialidad = Column(String)
    telefono = Column(String)
    clinica_id = Column(Integer, ForeignKey('clinica.id'))

    usuario = relationship("Usuario", back_populates="medico")
    clinica = relationship("Clinica", back_populates="medico")
    receta = relationship("Receta", back_populates="medico")
    
class Paciente(Base):
    __tablename__ = 'paciente'

    id = Column(Integer, primary_key=True, index=True)
    usuario_id = Column(Integer, ForeignKey('usuario.id'))  # Relación con la tabla usuarios
    nombre = Column(String)
    apellido_paterno = Column(String)
    apellido_materno = Column(String)
    telefono = Column(String)
    clinica_id = Column(Integer, ForeignKey('clinica.id'))

    usuario = relationship("Usuario", back_populates="paciente")
    clinica = relationship("Clinica", back_populates="paciente")
    receta = relationship("Receta", back_populates="paciente")
    
class Farmaceutico(Base):
    __tablename__ = 'farmaceutico'

    id = Column(Integer, primary_key=True, index=True)
    usuario_id = Column(Integer, ForeignKey('usuario.id'))  # Relación con la tabla de usuarios
    nombre = Column(String)
    apellido_paterno = Column(String)
    apellido_materno = Column(String, nullable=True)
    telefono = Column(String)
    farmacia_id = Column(Integer, ForeignKey('farmacia.id'))

    usuario = relationship("Usuario", back_populates="farmaceutico")
    receta = relationship("Receta", back_populates="farmaceutico")
    farmacia = relationship("Farmacia", back_populates="farmaceutico")
    
class Clinica(Base):
    __tablename__ = 'clinica'

    id = Column(Integer, primary_key=True, index=True)
    nombre = Column(String)
    tipo = Column(String)

    # Relación de una clínica con sus pacientes y médicos
    medico = relationship("Medico", back_populates="clinica")
    paciente = relationship("Paciente", back_populates="clinica")
    
class Farmacia(Base):
    __tablename__ = 'farmacia'

    id = Column(Integer, primary_key=True, index=True)
    nombre = Column(String)
    direccion = Column(String)
    telefono = Column(String)
    
    farmaceutico = relationship("Farmaceutico", back_populates="farmacia")

class Receta(Base):
    __tablename__ = 'receta'

    id = Column(Integer, primary_key=True, index=True)
    paciente_id = Column(Integer, ForeignKey('paciente.id'), nullable=False)
    medico_id = Column(Integer, ForeignKey('medico.id'), nullable=False)
    farmaceutico_id = Column(Integer, ForeignKey('farmaceutico.id'), nullable=True)
    fecha_emision = Column(TIMESTAMP, default=datetime.utcnow, nullable=False)
    fecha_vencimiento = Column(TIMESTAMP, nullable=False)
    estado = Column(String(50), nullable=False, default='emitida')
    fecha_surtido = Column(TIMESTAMP, nullable=True)
    receta_cifrada = Column(String)
    nonce = Column(String)
    tag = Column(String)
    firma = Column(String)
    clave_aes = Column(String)

    # Relaciones con otras tablas
    paciente = relationship("Paciente", back_populates="receta")
    medico = relationship("Medico", back_populates="receta")
    farmaceutico = relationship("Farmaceutico", back_populates="receta")

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Permite todas las solicitudes de cualquier origen
    allow_credentials=True,
    allow_methods=["*"],  # Permite todos los métodos (GET, POST, etc.)
    allow_headers=["*"],  # Permite todos los encabezados
)

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
    clinica_id: int

    class Config:
        orm_mode = True
        
class MedicoCreate(UsuarioCreate):
    nombre: str
    apellido_paterno: str
    apellido_materno: str
    especialidad: str
    telefono: str
    clinica_id: int  # Relación con la clínica
    
class PacienteCreate(UsuarioCreate):
    nombre: str
    apellido_paterno: str
    apellido_materno: str
    telefono: str
    clinica_id: int  # Relación con la clínica
    
class FarmaceuticoCreate(UsuarioCreate):
    nombre: str
    apellido_paterno: str
    apellido_materno: str
    telefono: str
    farmacia_id: int  # Relación con la clínica
    clinica_id: Optional[int] = None

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
async def create_usuario(usuario: Union[MedicoCreate, PacienteCreate, FarmaceuticoCreate], db: Session = Depends(get_db)):
    # Verificar si el username ya existe
    existing_user = db.query(Usuario).filter(Usuario.username == usuario.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="El nombre de usuario ya está registrado.")

    # Crear una nueva instancia de Usuario y agregarla a la base de datos
    hashed_password = hash_password(usuario.password)  # Generar el hash de la contraseña
    new_user = Usuario(
        username=usuario.username,
        password_hash=hashed_password,
        tipo_usuario=usuario.tipo_usuario
    )

    db.add(new_user)
    db.commit()  # Guardar el usuario en la tabla de usuarios
    db.refresh(new_user)  # Obtener el id generado

    if usuario.tipo_usuario in ['medico', 'paciente']:
        clinica = db.query(Clinica).filter(Clinica.id == usuario.clinica_id).first()
        if not clinica:
            raise HTTPException(status_code=400, detail="La clínica no existe.")
    
    if usuario.tipo_usuario == 'farmaceutico':
        farmacia = db.query(Farmacia).filter(Farmacia.id == usuario.farmacia_id).first()
        if not farmacia:
            raise HTTPException(status_code=400, detail="La farmacia no existe.")

    # Dependiendo del tipo de usuario, crear la entrada en la tabla correspondiente
    if usuario.tipo_usuario == 'medico':
        medico = Medico(
            usuario_id=new_user.id,
            nombre=usuario.nombre,
            apellido_paterno=usuario.apellido_paterno,
            apellido_materno=usuario.apellido_materno,
            especialidad=usuario.especialidad,  # Recibido desde el frontend
            telefono=usuario.telefono,
            clinica_id=usuario.clinica_id  # Asignar clínica al médico
        )
        db.add(medico)
        db.commit()

        # Devolvemos la respuesta con los datos del médico
        return {"id": new_user.id, "username": new_user.username, "tipo_usuario": new_user.tipo_usuario, 
                "nombre": medico.nombre, "apellido_paterno": medico.apellido_paterno, "especialidad": medico.especialidad, 
                "clinica": clinica.nombre}
        
    if usuario.tipo_usuario == 'paciente':
        paciente = Paciente(
            usuario_id=new_user.id,
            nombre=usuario.nombre,
            apellido_paterno=usuario.apellido_paterno,
            apellido_materno=usuario.apellido_materno,
            telefono=usuario.telefono,
            clinica_id=usuario.clinica_id  # Asignar clínica al médico
        )
        db.add(paciente)
        db.commit()

        # Devolvemos la respuesta con los datos del médico
        return {"id": new_user.id, "username": new_user.username, "tipo_usuario": new_user.tipo_usuario, 
                "nombre": paciente.nombre, "apellido_paterno": paciente.apellido_paterno, "clinica": clinica.nombre}
        
    if usuario.tipo_usuario == 'farmaceutico':
        farmaceutico = Farmaceutico(
            usuario_id=new_user.id,
            nombre=usuario.nombre,
            apellido_paterno=usuario.apellido_paterno,
            apellido_materno=usuario.apellido_materno,
            telefono=usuario.telefono,
            farmacia_id=usuario.farmacia_id
        )
        db.add(farmaceutico)
        db.commit()

        # Devolvemos la respuesta con los datos del médico
        return {"id": new_user.id, "username": new_user.username, "tipo_usuario": new_user.tipo_usuario, 
                "nombre": farmaceutico.nombre, "apellido_paterno": farmaceutico.apellido_paterno, "farmacia": farmaceutico.farmacia}
    
    # Si el tipo de usuario no es reconocido
    raise HTTPException(status_code=400, detail="Tipo de usuario no válido.")



from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session


from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from passlib.context import CryptContext
import os, serialization

from .database import get_db
from .models import Usuario, Medico, Paciente, Farmaceutico
from .security import generate_ed25519_keys, generate_x25519_keys, TEMP_DIR

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
app = FastAPI()


@app.post("/login/")
async def login(username: str, password: str, db: Session = Depends(get_db)):
    # 1) Validar existencia de usuario y contraseña
    user = db.query(Usuario).filter(Usuario.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    if not pwd_context.verify(password, user.password_hash):
        raise HTTPException(status_code=401, detail="Contraseña incorrecta")

    # 2) Extraer sólo el id de la tabla correspondiente
    if user.tipo_usuario == "medico":
        category_id = db.query(Medico.id) \
                        .filter(Medico.usuario_id == user.id) \
                        .scalar()
    elif user.tipo_usuario == "paciente":
        category_id = db.query(Paciente.id) \
                        .filter(Paciente.usuario_id == user.id) \
                        .scalar()
    else:  # farmacéutico
        category_id = db.query(Farmaceutico.id) \
                        .filter(Farmaceutico.usuario_id == user.id) \
                        .scalar()

    if category_id is None:
        raise HTTPException(status_code=404, detail=f"{user.tipo_usuario.capitalize()} no encontrado")

    # 3) Si ya existían llaves, devolvemos ambos IDs y metadatos
    if user.llavesgeneradas:
        return {
            "usuario_id":   user.id,
            "category_id":  category_id,
            "username":     user.username,
            "tipo_usuario": user.tipo_usuario
        }

    # 4) Primer login: generamos y almacenamos llaves
    priv_ed, pub_ed = generate_ed25519_keys()
    priv_x,   pub_x   = generate_x25519_keys()
    user.public_key_ed   = pub_ed
    user.public_key_x255 = pub_x
    user.llavesgeneradas = True
    db.commit()

    # 5) Guardar PEMs en TEMP_DIR
    ed_pem = priv_ed.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    x_pem = priv_x.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    ed_path   = os.path.join(TEMP_DIR, f"private_key_ed_{username}.pem")
    x255_path = os.path.join(TEMP_DIR, f"private_key_x255_{username}.pem")
    with open(ed_path,   "wb") as f: f.write(ed_pem)
    with open(x255_path, "wb") as f: f.write(x_pem)

    # 6) Devolver IDs, llaves públicas y URL del ZIP
    return {
        "usuario_id":      user.id,
        "category_id":     category_id,
        "username":        user.username,
        "tipo_usuario":    user.tipo_usuario,
        "public_key_ed":   pub_ed,
        "public_key_x255": pub_x,
        "private_key_zip": f"/download/keys/{username}"
    }


@app.get("/download/keys/{filename}")
async def download_all_keys(username: str):
    """
    Empaqueta private_key_ed_<username>.pem y private_key_x255_<username>.pem 
    en un ZIP y lo devuelve en una sola respuesta.
    """
    # Rutas de los archivos
    ed_path   = os.path.join(TEMP_DIR, f"private_key_ed_{username}.pem")
    x255_path = os.path.join(TEMP_DIR, f"private_key_x255_{username}.pem")

    # Validar que existan ambos
    if not os.path.exists(ed_path) or not os.path.exists(x255_path):
        raise HTTPException(status_code=404, detail="Alguna de las claves no existe")

    # Crear un ZIP en memoria
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as zipf:
        zipf.write(ed_path,   arcname=os.path.basename(ed_path))
        zipf.write(x255_path, arcname=os.path.basename(x255_path))
    buffer.seek(0)

    # Devolverlo como streaming
    return StreamingResponse(
        buffer,
        media_type="application/zip",
        headers={"Content-Disposition": f"attachment; filename=keys_{username}.zip"}
    )

@app.post("/firmar_receta/")
async def firmar_receta(
    paciente_id: int = Form(...),
    medico_id: int = Form(...),
    farmaceutico_id: int = Form(...),
    fecha_vencimiento: str = Form(...),
    estado: str = Form("emitida"),
    mensaje: str = Form(...),
    private_key_file_ed: UploadFile = File(...),  # Clave privada Ed25519
    private_key_file_x255: UploadFile = File(...),  # Clave privada X25519
    db: Session = Depends(get_db)
):
    try:
        # Verificar si el paciente y el médico existen
        paciente = db.query(Paciente).filter(Paciente.id == paciente_id).first()
        medico = db.query(Medico).filter(Medico.id == medico_id).first()
        farmaceutico = db.query(Farmaceutico).filter(Farmaceutico.id == farmaceutico_id).first()

        if not paciente or not medico or not farmaceutico:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")

        # Cargar las claves privadas
        private_key_ed_pem = await private_key_file_ed.read()
        private_key_ed = serialization.load_pem_private_key(private_key_ed_pem, password=None, backend=default_backend())

        private_key_x255_pem = await private_key_file_x255.read()
        private_key_x255 = serialization.load_pem_private_key(private_key_x255_pem, password=None, backend=default_backend()) # Cargar clave privada X25519

        # Obtener la clave pública de X25519 del médico desde la base de datos
        public_key_x255_pem_medico = medico.usuario.public_key_x255
        if not public_key_x255_pem_medico:
            raise HTTPException(status_code=404, detail="Clave pública X25519 no encontrada")
        
        public_key_x255_pem_paciente = paciente.usuario.public_key_x255
        if not public_key_x255_pem_paciente:
            raise HTTPException(status_code=404, detail="Clave pública X25519 no encontrada")
        
        public_key_x255_pem_farmaceutico = farmaceutico.usuario.public_key_x255
        if not public_key_x255_pem_farmaceutico:
            raise HTTPException(status_code=404, detail="Clave pública X25519 no encontrada")

         # Generar la clave de AES con el intercambio de claves X25519
        aes_key = intercambiar_claves_x25519(private_key_x255_pem, public_key_x255_pem_paciente)  # Generar la clave AES con la clave pública del paciente

        # Cifrar el mensaje (receta) con la clave AES
        ciphertext, nonce, tag = cifrar_con_aes_gcm(mensaje, aes_key)

        # Firmar el mensaje con la clave privada Ed25519
        signature = firmar_mensaje_con_ed25519(private_key_ed, mensaje)
        
        firma_hex = signature.hex()  # Convertir la firma a hexadecimal
        nonce_hex = nonce.hex()  # Convertir el nonce a hexadecimal
        tag_hex = tag.hex()  # Convertir el tag a hexadecimal
        aes_key_hex = aes_key.hex()  # Convertir la clave AES a hexadecimal
        receta_cifrada_hex = ciphertext.hex()  # Convertir la receta cifrada a hexadecimal

        # Crear la receta y almacenar en la base de datos (clave AES cifrada para cada usuario)
        nueva_receta = Receta(
            paciente_id=paciente_id,
            medico_id=medico_id,
            farmaceutico_id=farmaceutico_id,
            estado="emitida",  # Ejemplo de estado
            fecha_emision=datetime.utcnow(),
            fecha_vencimiento=fecha_vencimiento,
            receta_cifrada=receta_cifrada_hex,  # Guardar el mensaje cifrado
            nonce=nonce_hex,  # Guardar el nonce
            tag=tag_hex,  # Guardar el tag
            firma=firma_hex,  # Guardar la firma
            clave_aes=aes_key_hex
        )

        db.add(nueva_receta)
        db.commit()
        db.refresh(nueva_receta)

        return {"message": "Receta firmada y cifrada con éxito", "receta_id": nueva_receta.id}
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error al firmar la receta: {e}")
    
@app.post("/verificar_firma/")
async def verificar_firma(
    idreceta: int,  # Recibimos el idreceta
    db: Session = Depends(get_db)
):
    try:
        # Obtener la receta desde la base de datos usando el idreceta
        receta = db.query(Receta).filter(Receta.id == idreceta).first()
        if not receta:
            raise HTTPException(status_code=404, detail="Receta no encontrada")

        # Obtener el médico de la receta
        medico_id = receta.medico_id
        if not medico_id:
            raise HTTPException(status_code=404, detail="Médico no asociado a la receta")
        
        # Obtener el médico desde la base de datos
        medico = db.query(Medico).filter(Medico.id == medico_id).first()
        if not medico:
            raise HTTPException(status_code=404, detail="Médico no encontrado")

        # Obtener la clave pública del médico desde la base de datos
        public_key_pem = medico.usuario.public_key_ed
        if not public_key_pem:
            raise HTTPException(status_code=404, detail="Clave pública no encontrada para el médico")

        # Cargar la clave pública desde el formato PEM
        public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))

        # Extraer la firma almacenada en la receta
        firma = bytes.fromhex(receta.firma)  # Convertimos la firma de hex a bytes

        # Obtener la clave AES (clave compartida derivada del intercambio de claves X25519)
        aes_key = bytes.fromhex(receta.clave_aes)

        # Obtener el nonce y el tag (guardados en la base de datos)
        nonce = bytes.fromhex(receta.nonce)
        tag = bytes.fromhex(receta.tag)

        # Desencriptar el mensaje utilizando AES-GCM
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()

        # Desencriptar el mensaje
        try:
            mensaje_descifrado = decryptor.update(bytes.fromhex(receta.receta_cifrada)) + decryptor.finalize()
        except Exception as e:
            raise HTTPException(status_code=400, detail="Error al descifrar el mensaje")

        # Verificar la firma usando Ed25519
        ed_key = public_key if isinstance(public_key, ed25519.Ed25519PublicKey) else None
        if not ed_key:
            raise HTTPException(status_code=400, detail="Clave pública no es de tipo Ed25519")

        # Verificar la firma con el mensaje descifrado
        ed_key.verify(firma, mensaje_descifrado)  # Verificar firma sin padding ni hash

        # Si la firma es válida, devolver un mensaje de éxito
        return {"message": "Firma verificada correctamente"}

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error al verificar la firma: {str(e)}")
    
def generate_x25519_keys():
    
    # Generar la clave privada
    private_key = X25519PrivateKey.generate()

    # Obtener la clave pública
    public_key = private_key.public_key()

    # Serializar las llaves a formato PEM para que puedan ser enviadas
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,  # Cambiado a PKCS8
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_key, public_pem.decode("utf-8")

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

# Función para intercambiar las claves X25519
def intercambiar_claves_x25519(private_key_pem, public_key_pem):
    # Cargar las claves desde los archivos PEM
    private_key = serialization.load_pem_private_key(private_key_pem, password=None, backend=default_backend())
    public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'), backend=default_backend())

    # Realizar el intercambio de claves para obtener una clave compartida
    shared_key = private_key.exchange(public_key)

    # Usamos directamente la clave compartida como clave AES (32 bytes)
    aes_key = shared_key[:32]  # Asegurarnos de que sea de 256 bits (32 bytes)

    return aes_key

# Función para cifrar el mensaje usando AES-GCM
def cifrar_con_aes_gcm(mensaje: str, key: bytes):
    # Generar un nonce aleatorio de 12 bytes
    nonce = os.urandom(12)

    # Convertir el mensaje a bytes
    data = mensaje.encode()

    # Crear el cifrador AES-GCM
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()

    # Cifrar el mensaje
    ciphertext = encryptor.update(data) + encryptor.finalize()

    # Obtener el tag de autenticación
    tag = encryptor.tag

    return ciphertext, nonce, tag

# Función para firmar el mensaje con Ed25519
def firmar_mensaje_con_ed25519(private_key, mensaje):
    # Firma del mensaje con la clave privada Ed25519
    signature = private_key.sign(mensaje.encode())
    return signature

# Endpoint para obtener las recetas de un paciente específico
@app.get("/recetas/paciente/{paciente_id}")
async def recetas_por_paciente(paciente_id: int, db: Session = Depends(get_db)):
    recetas = db.query(Receta).filter(Receta.paciente_id == paciente_id).all()
    return {"recetas": [r.id for r in recetas]}

# Consulta de recetas emitidas por un médico específico
@app.get("/recetas/medico/{medico_id}")
async def recetas_por_medico(medico_id: int, db: Session = Depends(get_db)):
    recetas = db.query(Receta).filter(Receta.medico_id == medico_id).all()
    return {"recetas": [r.id for r in recetas]}

# Consulta de recetas asignadas a un farmacéutico específico
@app.get("/recetas/farmaceutico/{farmaceutico_id}")
async def recetas_por_farmaceutico(farmaceutico_id: int, db: Session = Depends(get_db)):
    recetas = db.query(Receta).filter(Receta.farmaceutico_id == farmaceutico_id).all()
    return {"recetas": [r.id for r in recetas]}

# Surtir una receta y actualizar su estado
@app.post("/recetas/surtir/{receta_id}")
async def surtir_receta(
    receta_id: int,
    farmaceutico_id: int = Form(...),
    private_key_file_x255: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    receta = db.query(Receta).filter(Receta.id == receta_id).first()
    if not receta:
        raise HTTPException(status_code=404, detail="Receta no encontrada")
    
    if receta.estado != "emitida":
        raise HTTPException(status_code=400, detail="La receta ya fue surtida o está cancelada")
    
    if receta.fecha_vencimiento < datetime.utcnow():
        raise HTTPException(status_code=400, detail="La receta está vencida")

    # Verificar farmacéutico válido
    farmaceutico = db.query(Farmaceutico).filter(Farmaceutico.id == farmaceutico_id).first()
    if not farmaceutico:
        raise HTTPException(status_code=404, detail="Farmacéutico no encontrado")
    
    # Clave pública del paciente
    paciente = receta.paciente
    if not paciente.usuario.public_key_x255:
        raise HTTPException(status_code=404, detail="Clave pública del paciente no encontrada")
    
    # Leer clave privada del farmacéutico
    private_key_x255_pem = await private_key_file_x255.read()
    
    # Derivar clave AES y descifrar mensaje
    try:
        aes_key = bytes.fromhex(receta.clave_aes) 
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(bytes.fromhex(receta.nonce), bytes.fromhex(receta.tag)), backend=default_backend())
        decryptor = cipher.decryptor()
        mensaje = decryptor.update(bytes.fromhex(receta.receta_cifrada)) + decryptor.finalize()
    except Exception as e:
        raise HTTPException(status_code=400, detail="Error al descifrar la receta")

    # Marcar receta como surtida
    receta.estado = "surtida"
    receta.fecha_surtido = datetime.utcnow()
    receta.farmaceutico_id = farmaceutico_id
    db.commit()

    return {
        "message": "Receta surtida con éxito",
        "receta_id": receta.id,
        "contenido_receta": mensaje.decode()
    }

# Listado de recetas por paciente
@app.get("/recetas/paciente/{paciente_id}")
async def recetas_por_paciente(paciente_id: int, db: Session = Depends(get_db)):
    recetas = db.query(Receta).filter(Receta.paciente_id == paciente_id).all()
    return {
        "recetas": [
            {
                "id": r.id,
                "fecha_emision": r.fecha_emision,
                "fecha_vencimiento": r.fecha_vencimiento,
                "estado": r.estado,
                "medico": r.medico.nombre,
                "firma_valida": r.firma is not None
            } for r in recetas
        ]
    }
# Endpoint para ver el contenido descrifrado de una receta
@app.post("/recetas/ver_contenido/{receta_id}")
async def ver_receta_paciente(
    receta_id: int,
    private_key_file_x255: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    receta = db.query(Receta).filter(Receta.id == receta_id).first()
    if not receta:
        raise HTTPException(status_code=404, detail="Receta no encontrada")

    # Validación: solo el paciente debe poder ver esta receta
    public_key_paciente = receta.paciente.usuario.public_key_x255
    if not public_key_paciente:
        raise HTTPException(status_code=404, detail="Clave pública no encontrada")

    # Leer clave privada del paciente
    private_key_x255_pem = await private_key_file_x255.read()

    try:
        aes_key = intercambiar_claves_x25519(private_key_x255_pem, public_key_paciente)
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(bytes.fromhex(receta.nonce), bytes.fromhex(receta.tag)), backend=default_backend())
        decryptor = cipher.decryptor()
        mensaje = decryptor.update(bytes.fromhex(receta.receta_cifrada)) + decryptor.finalize()
    except Exception as e:
        raise HTTPException(status_code=400, detail="Error al descifrar la receta")

    return {
        "mensaje_descifrado": mensaje.decode()
    }
@app.get("/download/keys/{username}")
async def download_all_keys(username: str):
    """
    Empaqueta private_key_ed_<username>.pem y private_key_x255_<username>.pem 
    en un ZIP y lo devuelve en una sola respuesta.
    """
    ed_path   = os.path.join(TEMP_DIR, f"private_key_ed_{username}.pem")
    x255_path = os.path.join(TEMP_DIR, f"private_key_x255_{username}.pem")

    if not os.path.exists(ed_path) or not os.path.exists(x255_path):
        raise HTTPException(status_code=404, detail="Alguna de las claves no existe")

    buffer = BytesIO()
    with zipfile.ZipFile(buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as zipf:
        zipf.write(ed_path,   arcname=os.path.basename(ed_path))
        zipf.write(x255_path, arcname=os.path.basename(x255_path))
    buffer.seek(0)

    return StreamingResponse(
        buffer,
        media_type="application/zip",
        headers={"Content-Disposition": f"attachment; filename=keys_{username}.zip"}
    )

