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

@app.post("/login/")
async def login(username: str, password: str, db: Session = Depends(get_db)):
    user = db.query(Usuario).filter(Usuario.username == username).first()

    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    
    if not pwd_context.verify(password, user.password_hash):
        raise HTTPException(status_code=401, detail="Contraseña incorrecta")

    if user.llavesgeneradas:
        return {"username": user.username, "tipo_usuario": user.tipo_usuario}
    
    private_key_ed, public_key_ed = generate_ed25519_keys()
    private_key_x255, public_key_x255 = generate_x25519_keys()
    
    user.public_key_ed = public_key_ed
    user.public_key_x255 = public_key_x255
    user.llavesgeneradas = True
    db.commit()

    # Guardar las claves privadas en archivos temporales
    private_key_ed_pem = private_key_ed.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    private_key_x255_pem = private_key_x255.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Guardar los archivos en el sistema de archivos temporal
    ed_file_path = os.path.join(TEMP_DIR, f"private_key_ed_{username}.pem")
    x255_file_path = os.path.join(TEMP_DIR, f"private_key_x255_{username}.pem")

    with open(ed_file_path, "wb") as ed_file:
        ed_file.write(private_key_ed_pem)

    with open(x255_file_path, "wb") as x255_file:
        x255_file.write(private_key_x255_pem)

    # Devolver las URLs de los archivos generados
    return {
        "username": user.username,
        "tipo_usuario": user.tipo_usuario,
        "public_key_ed": public_key_ed,
        "public_key_x255": public_key_x255,
        "private_key_ed_file": {"url": f"/download/{os.path.basename(ed_file_path)}"},
        "private_key_x255_file": {"url": f"/download/{os.path.basename(x255_file_path)}"}
    }

@app.get("/download/{filename}")
async def download_file(filename: str):
    file_path = os.path.join(TEMP_DIR, filename)

    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")
    
    return FileResponse(file_path, media_type="application/pem", filename=filename)

@app.post("/firmar_receta/")
async def firmar_receta(
    paciente_id: int = Form(...),
    medico_id: int = Form(...),
    fecha_vencimiento: str = Form(...),
    estado: str = Form("emitida"),
    mensaje: str = Form(...),
    private_key_file_ed: UploadFile = File(...),  # Clave privada Ed25519
    private_key_file_x255: UploadFile = File(...),  # Clave privada X25519
    db: Session = Depends(get_db)
):
    # Verificar si el paciente y el médico existen
    paciente = db.query(Paciente).filter(Paciente.id == paciente_id).first()
    medico = db.query(Medico).filter(Medico.id == medico_id).first()

    if not paciente or not medico:
        raise HTTPException(status_code=404, detail="Paciente o médico no encontrado")

    # Leer la clave privada Ed25519 desde el archivo .pem
    private_key_ed_pem = await private_key_file_ed.read()
    private_key_ed = cargar_clave_privada(private_key_ed_pem, clave_tipo="ed25519")  # Cargar clave privada Ed25519

    # Leer la clave privada X25519 desde el archivo .pem
    private_key_x255_pem = await private_key_file_x255.read()
    private_key_x255 = cargar_clave_privada(private_key_x255_pem, clave_tipo="x25519")  # Cargar clave privada X25519

    # Obtener la clave pública de X25519 del médico desde la base de datos
    public_key_x255_pem = medico.usuario.public_key_x255
    if not public_key_x255_pem:
        raise HTTPException(status_code=404, detail="Clave pública X25519 no encontrada")

    # Realizar el intercambio de claves y obtener la clave AES
    aes_key = intercambiar_claves_x25519(private_key_x255.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()), public_key_x255_pem)

    # Cifrar el mensaje con AES-GCM
    ciphertext, nonce, tag = cifrar_con_aes_gcm(mensaje, aes_key)

    # Firmar el mensaje utilizando la clave privada Ed25519
    signature = firmar_mensaje_con_ed25519(private_key_ed, mensaje)

    # Crear la receta con los datos proporcionados
    nueva_receta = Receta(
        paciente_id=paciente_id,
        medico_id=medico_id,
        fecha_emision=datetime.utcnow(),
        fecha_vencimiento=datetime.fromisoformat(fecha_vencimiento),
        estado=estado,
    )

    db.add(nueva_receta)
    db.commit()
    db.refresh(nueva_receta)

    # Guardar el archivo cifrado en el directorio temporal
    file_name = f"receta_firmada_{nueva_receta.id}.txt"
    file_path = os.path.join(TEMP_DIR, file_name)
    with open(file_path, "wb") as file:
        # Guardamos el nonce, el texto cifrado, el tag y la firma
        file.write(nonce + ciphertext + tag + signature)

    return {
        "message": "Receta firmada y cifrada con éxito.",
        "receta_id": nueva_receta.id,
        "download_url": f"/download/{file_name}"  # URL del archivo generado
    }
    
@app.post("/verificar_firma/")
async def verificar_firma(
    archivo_firma: UploadFile = File(...),  # Recibimos el archivo que contiene el mensaje y la firma
    db: Session = Depends(get_db)
):
    # Leer el archivo que contiene el idreceta, mensaje y la firma
    file_content = await archivo_firma.read()

    # Dividir el archivo en el idreceta, mensaje y firma (buscando las líneas correspondientes)
    try:
        file_content_str = file_content.decode('utf-8')
        # Extraer el idreceta
        idreceta_str = file_content_str.split("idreceta:")[1].split("\n")[0].strip()
        # Extraer el mensaje
        mensaje = file_content_str.split("Mensaje:")[1].split("Firma Digital:")[0].strip()
        # Extraer la firma digital
        firma_hex = file_content_str.split("Firma Digital:")[1].strip()

        # Convertir receta_id de string a entero
        try:
            idreceta = int(idreceta_str)
        except ValueError:
            raise HTTPException(status_code=400, detail="Receta ID no válido")
    except ValueError:
        raise HTTPException(status_code=400, detail="El archivo no tiene el formato esperado")

    # Convertir la firma de hexadecimal a bytes
    try:
        firma = bytes.fromhex(firma_hex)
    except ValueError:
        raise HTTPException(status_code=400, detail="Firma no válida")

    # Obtener la receta desde la base de datos usando el idreceta
    receta = db.query(Receta).filter(Receta.id == idreceta).first()
    if not receta:
        raise HTTPException(status_code=404, detail="Receta no encontrada")

    # Obtener el medico_id de la receta
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

    try:
        # Cargar la clave pública desde el formato PEM
        public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
    except Exception as e:
        raise HTTPException(status_code=400, detail="Error al cargar la clave pública")

    # Usar Ed25519PublicKey para verificar la firma
    try:
        # Convertir la clave pública a Ed25519PublicKey
        ed_key = public_key if isinstance(public_key, ed25519.Ed25519PublicKey) else None
        if not ed_key:
            raise HTTPException(status_code=400, detail="Clave pública no es de tipo Ed25519")

        # Verificar la firma usando Ed25519
        ed_key.verify(firma, mensaje.encode())  # Verificar firma sin padding ni hash
        return {"message": "Firma verificada correctamente"}
    except Exception as e:
        raise HTTPException(status_code=400, detail="Firma no válida")
    
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

def intercambiar_claves_x25519(private_key_pem, public_key_pem):
    # Cargar la clave privada X25519 desde el archivo PEM y convertirla a bytes crudos
    private_key = serialization.load_pem_private_key(private_key_pem, password=None, backend=default_backend())

    # Convertir la clave privada X25519 a bytes crudos
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Cargar la clave pública X25519 desde el archivo PEM
    public_key = x25519.X25519PublicKey.from_public_bytes(public_key_pem.encode('utf-8'))  # Convertir a bytes

    # Realizar el intercambio de claves
    shared_key = private_key.exchange(public_key)

    # Usar el shared_key directamente para generar una clave AES
    key = hashes.Hash(hashes.SHA256(), backend=default_backend())
    key.update(shared_key)
    aes_key = key.finalize()  # Esto genera una clave de 32 bytes (256 bits)

    return aes_key

# Cifrado con AES-GCM
def cifrar_con_aes_gcm(mensaje: str, key: bytes):
    # Generar un nonce aleatorio para AES-GCM (12 bytes recomendado)
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
def firmar_mensaje_con_ed25519(private_key_ed, mensaje):
    # Firma del mensaje con la clave privada Ed25519
    signature = private_key_ed.sign(mensaje.encode())  # Firma el mensaje
    return signature

# Función para cargar la clave privada
def cargar_clave_privada(private_key_pem, clave_tipo="ed25519"):
    try:
        if clave_tipo == "ed25519":
            # Cargar la clave privada Ed25519 desde el archivo PEM
            private_key = serialization.load_pem_private_key(private_key_pem, password=None, backend=default_backend())
            return private_key
        elif clave_tipo == "x25519":
            # Cargar la clave privada X25519 desde el archivo PEM
            private_key = serialization.load_pem_private_key(private_key_pem, password=None, backend=default_backend())
            return private_key
        else:
            raise HTTPException(status_code=400, detail="Tipo de clave desconocido.")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"No se pudo cargar la clave privada: {e}")
