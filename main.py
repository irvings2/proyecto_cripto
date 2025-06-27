from fastapi import FastAPI, Depends, HTTPException, File, UploadFile, Form
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, Boolean, ForeignKey, Text, TIMESTAMP
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from sqlalchemy import select
from pydantic import BaseModel
from passlib.context import CryptContext
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, padding
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
from fastapi import Query
import os
import base64

DATABASE_URL = "postgresql://postgres.gijqjegotyhtdbngcuth:nedtu3-ruqvec-mixSew@aws-0-us-east-2.pooler.supabase.com:6543/postgres"

engine = create_engine(DATABASE_URL, pool_size=10, max_overflow=20)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

TEMP_DIR = "temp"

# Crear directorio si no existe
if not os.path.exists(TEMP_DIR):
    os.makedirs(TEMP_DIR)
    
# Ruta de almacenamiento de las llaves
private_key_path = "private_key.pem"
public_key_path = "public_key.pem"

# Declarative Base para las tablas
Base = declarative_base()

class Usuario(Base):
    __tablename__ = 'usuario'  
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
    usuario_id = Column(Integer, ForeignKey('usuario.id'))  
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
    usuario_id = Column(Integer, ForeignKey('usuario.id')) 
    nombre = Column(String)
    apellido_paterno = Column(String)
    apellido_materno = Column(String)
    telefono = Column(String)
    clinica_id = Column(Integer, ForeignKey('clinica.id'), nullable=True)

    usuario = relationship("Usuario", back_populates="paciente")
    clinica = relationship("Clinica", back_populates="paciente")
    receta = relationship("Receta", back_populates="paciente")
    
class Farmaceutico(Base):
    __tablename__ = 'farmaceutico'

    id = Column(Integer, primary_key=True, index=True)
    usuario_id = Column(Integer, ForeignKey('usuario.id'))
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

    paciente = relationship("Paciente", back_populates="receta")
    medico = relationship("Medico", back_populates="receta")
    farmaceutico = relationship("Farmaceutico", back_populates="receta")

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  
    allow_credentials=True,
    allow_methods=["*"],  
    allow_headers=["*"],  
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
        

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
    clinica_id: int  
    
class PacienteCreate(UsuarioCreate):
    nombre: str
    apellido_paterno: str
    apellido_materno: str
    telefono: str
    clinica_id: Optional[int] = None  
    
class FarmaceuticoCreate(UsuarioCreate):
    nombre: str
    apellido_paterno: str
    apellido_materno: str
    telefono: str
    farmacia_id: int  
    clinica_id: Optional[int] = None

# Configuración de passlib para el hash de la contraseña
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Función para generar el hash de la contraseña
def hash_password(password: str):
    return pwd_context.hash(password)

# Función para generar las llaves ED25519
def generate_ed25519_keys():
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    return private_key, public_key_pem

# Función para generar las llaves RSA
def generate_rsa_keys():
    # Generar par de llaves RSA
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    # Guardar las llaves en archivos
    with open(private_key_path, "wb") as private_file:
        private_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(public_key_path, "wb") as public_file:
        public_file.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    return private_key, public_key

def load_public_key():
    with open(public_key_path, "rb") as public_key_file:
        public_key = serialization.load_pem_public_key(public_key_file.read())
    return public_key

def load_private_key():
    with open(private_key_path, "rb") as private_key_file:
        private_key = serialization.load_pem_private_key(private_key_file.read(), password=None)
    return private_key

# Función para generar una clave AES-GCM de 256 bits
def generate_aes_key():
    return os.urandom(32)  # 32 bytes = 256 bits

# Función para cifrar la clave AES con RSA-OAEP
def encrypt_aes_key_with_rsa(aes_key: bytes, public_key):
    ciphertext = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(ciphertext).decode('utf-8')

def decrypt_aes_key_with_rsa(encrypted_aes_key: bytes, private_key):
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
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

@app.post("/generate_rsa_keys/")
async def generate_keys():
    try:
        # Verificar si las llaves ya existen, en caso contrario generarlas
        if not os.path.exists(private_key_path) or not os.path.exists(public_key_path):
            private_key, public_key = generate_rsa_keys()
        else:
            return {"message": "Las llaves RSA ya están generadas y almacenadas."}

        return {
            "message": "Llaves RSA generadas y guardadas correctamente",
            "private_key": private_key_path,
            "public_key": public_key_path
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail="Error al generar las llaves RSA: " + str(e))

@app.get("/usuarios/")
async def get_usuarios(db: Session = Depends(get_db)):

    query = select(Usuario)
    result = db.execute(query).scalars().all() 
    return {"usuarios": result}

@app.post("/usuarios/")
async def create_usuario(usuario: Union[MedicoCreate, PacienteCreate, FarmaceuticoCreate], db: Session = Depends(get_db)):
    # Verificar si el username ya existe
    existing_user = db.query(Usuario).filter(Usuario.username == usuario.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="El nombre de usuario ya está registrado.")


    hashed_password = hash_password(usuario.password) 
    new_user = Usuario(
        username=usuario.username,
        password_hash=hashed_password,
        tipo_usuario=usuario.tipo_usuario
    )

    db.add(new_user)
    db.commit()  # Guardar el usuario en la tabla de usuarios
    db.refresh(new_user) 

    clinica = None
    if usuario.tipo_usuario in ['medico', 'paciente']:
        if usuario.clinica_id is not None:
            clinica = db.query(Clinica).filter(Clinica.id == usuario.clinica_id).first()
            if not clinica:
                raise HTTPException(status_code=400, detail="La clínica no existe.")

    if usuario.tipo_usuario == 'farmaceutico':
        farmacia = db.query(Farmacia).filter(Farmacia.id == usuario.farmacia_id).first()
        if not farmacia:
            raise HTTPException(status_code=400, detail="La farmacia no existe.")

    if usuario.tipo_usuario == 'medico':
        medico = Medico(
            usuario_id=new_user.id,
            nombre=usuario.nombre,
            apellido_paterno=usuario.apellido_paterno,
            apellido_materno=usuario.apellido_materno,
            especialidad=usuario.especialidad,
            telefono=usuario.telefono,
            clinica_id=usuario.clinica_id
        )
        db.add(medico)
        db.commit()
        return {
            "id": new_user.id,
            "username": new_user.username,
            "tipo_usuario": new_user.tipo_usuario,
            "nombre": medico.nombre,
            "apellido_paterno": medico.apellido_paterno,
            "especialidad": medico.especialidad,
            "clinica": clinica.nombre if clinica else None
        }

    if usuario.tipo_usuario == 'paciente':
        paciente = Paciente(
            usuario_id=new_user.id,
            nombre=usuario.nombre,
            apellido_paterno=usuario.apellido_paterno,
            apellido_materno=usuario.apellido_materno,
            telefono=usuario.telefono,
            clinica_id=usuario.clinica_id
        )
        db.add(paciente)
        db.commit()
        return {
            "id": new_user.id,
            "username": new_user.username,
            "tipo_usuario": new_user.tipo_usuario,
            "nombre": paciente.nombre,
            "apellido_paterno": paciente.apellido_paterno,
            "clinica": clinica.nombre if clinica else None
        }

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
        return {
            "id": new_user.id,
            "username": new_user.username,
            "tipo_usuario": new_user.tipo_usuario,
            "nombre": farmaceutico.nombre,
            "apellido_paterno": farmaceutico.apellido_paterno,
            "farmacia": farmaceutico.farmacia
        }

    raise HTTPException(status_code=400, detail="Tipo de usuario no válido.")


@app.post("/login/")
async def login(username: str, password: str, db: Session = Depends(get_db)):
    user = db.query(Usuario).filter(Usuario.username == username).first()

    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    
    if not pwd_context.verify(password, user.password_hash):
        raise HTTPException(status_code=401, detail="Contraseña incorrecta")

    # Consulta para obtener el id de paciente, médico o farmacéutico
    id_tipo = None
    if user.tipo_usuario == "paciente":
        paciente = db.query(Paciente).filter(Paciente.usuario_id == user.id).first()
        id_tipo = paciente.id if paciente else None
    elif user.tipo_usuario == "medico":
        medico = db.query(Medico).filter(Medico.usuario_id == user.id).first()
        id_tipo = medico.id if medico else None
    elif user.tipo_usuario == "farmaceutico":
        farmaceutico = db.query(Farmaceutico).filter(Farmaceutico.usuario_id == user.id).first()
        id_tipo = farmaceutico.id if farmaceutico else None

    # Si las llaves ya están generadas, regresar solo los datos básicos
    if user.llavesgeneradas:
        return {
            "username": user.username,
            "tipo_usuario": user.tipo_usuario,
            "id_tipo": id_tipo,
        }
    
    private_key_ed, public_key_ed = generate_ed25519_keys()
    
    user.public_key_ed = public_key_ed
    user.llavesgeneradas = True
    db.commit()

    # Guardar las claves privadas en archivos temporales
    private_key_ed_pem = private_key_ed.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Guardar los archivos en el sistema de archivos temporal
    ed_file_path = os.path.join(TEMP_DIR, f"private_key_ed_{username}.pem")

    with open(ed_file_path, "wb") as ed_file:
        ed_file.write(private_key_ed_pem)

    # Devolver las URLs de los archivos generados
    return {
        "username": user.username,
        "tipo_usuario": user.tipo_usuario,
        "id_tipo": id_tipo,  # Nuevo campo con el ID correspondiente según el tipo
        "public_key_ed": public_key_ed,
        "private_key_ed_file": {"url": f"/download/{os.path.basename(ed_file_path)}"},
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
    farmaceutico_id: int = Form(...),
    fecha_vencimiento: str = Form(...),
    estado: str = Form("emitida"),
    mensaje: str = Form(...),
    private_key_file_ed: UploadFile = File(...),  # Clave privada Ed25519
    db: Session = Depends(get_db)
):
    try:
        # Verificar si el paciente y el médico existen
        paciente = db.query(Paciente).filter(Paciente.id == paciente_id).first()
        medico = db.query(Medico).filter(Medico.id == medico_id).first()
        farmaceutico = db.query(Farmaceutico).filter(Farmaceutico.id == farmaceutico_id).first()

        if not paciente or not medico or not farmaceutico:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        
        public_key = load_public_key()
        
        aes_key = generate_aes_key()

        # Cargar las claves privadas
        private_key_ed_pem = await private_key_file_ed.read()
        private_key_ed = serialization.load_pem_private_key(private_key_ed_pem, password=None, backend=default_backend())# Generar la clave AES con la clave pública del paciente

        # Cifrar el mensaje (receta) con la clave AES
        ciphertext, nonce, tag = cifrar_con_aes_gcm(mensaje, aes_key)
        
        encrypted_aes_key = encrypt_aes_key_with_rsa(aes_key, public_key)

        # Firmar el mensaje con la clave privada Ed25519
        signature = firmar_mensaje_con_ed25519(private_key_ed, mensaje)
        
        # A hexadecimal
        firma_hex = signature.hex() 
        nonce_hex = nonce.hex()  
        tag_hex = tag.hex() 
        receta_cifrada_hex = ciphertext.hex() 

        # Crear la receta y almacenar en la base de datos (clave AES cifrada para cada usuario)
        nueva_receta = Receta(
            paciente_id=paciente_id,
            medico_id=medico_id,
            farmaceutico_id=farmaceutico_id,
            estado="emitida",  
            fecha_emision=datetime.utcnow(),
            fecha_vencimiento=fecha_vencimiento,
            receta_cifrada=receta_cifrada_hex,  
            nonce=nonce_hex,  
            tag=tag_hex,  
            firma=firma_hex, 
            clave_aes=encrypted_aes_key
        )

        db.add(nueva_receta)
        db.commit()
        db.refresh(nueva_receta)

        return {"message": "Receta firmada y cifrada con éxito", "receta_id": nueva_receta.id}
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error al firmar la receta: {e}")
    
@app.post("/verificar_firma/")
async def verificar_firma(
    idreceta: int,  
    db: Session = Depends(get_db)
):
    try:
        # Obtener la receta desde la base de datos usando el idreceta
        receta = db.query(Receta).filter(Receta.id == idreceta).first()
        if not receta:
            raise HTTPException(status_code=404, detail="Receta no encontrada")

        medico_id = receta.medico_id
        if not medico_id:
            raise HTTPException(status_code=404, detail="Médico no asociado a la receta")
        
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

        # Obtener la clave AES cifrada desde la base de datos (cifrada con RSA)
        encrypted_aes_key = base64.b64decode(receta.clave_aes)

        # Cargar la clave privada RSA para descifrar la clave AES
        private_key = load_private_key()

        # Descifrar la clave AES
        aes_key = decrypt_aes_key_with_rsa(encrypted_aes_key, private_key)

        # Obtener el nonce y el tag (guardados en la base de datos)
        nonce = bytes.fromhex(receta.nonce)
        tag = bytes.fromhex(receta.tag)

        # descifrar el mensaje utilizando AES-GCM
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()

        # descifrar el mensaje
        try:
            mensaje_descifrado = decryptor.update(bytes.fromhex(receta.receta_cifrada)) + decryptor.finalize()
        except Exception as e:
            raise HTTPException(status_code=400, detail="Error al descifrar el mensaje")

        # Verificar la firma
        ed_key = public_key if isinstance(public_key, ed25519.Ed25519PublicKey) else None
        if not ed_key:
            raise HTTPException(status_code=400, detail="Clave pública no es de tipo Ed25519")

        ed_key.verify(firma, mensaje_descifrado) 

        return {"message": "Firma verificada correctamente"}

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error al verificar la firma: {str(e)}")

def firmar_mensaje_con_ed25519(private_key, mensaje):
    # Firma del mensaje con la clave privada Ed25519
    signature = private_key.sign(mensaje.encode())
    return signature

@app.get("/recetas/paciente/{paciente_id}")
async def recetas_por_paciente(paciente_id: int, db: Session = Depends(get_db)):
    recetas = db.query(Receta).filter(Receta.paciente_id == paciente_id).all()
    return {"recetas": [r.id for r in recetas]}

@app.get("/recetas/medico/{medico_id}")
async def recetas_por_medico(medico_id: int, db: Session = Depends(get_db)):
    recetas = db.query(Receta).filter(Receta.medico_id == medico_id).all()
    return {"recetas": [r.id for r in recetas]}

@app.get("/recetas/farmaceutico/{farmaceutico_id}")
async def recetas_por_farmaceutico(farmaceutico_id: int, db: Session = Depends(get_db)):
    recetas = db.query(Receta).filter(Receta.farmaceutico_id == farmaceutico_id).all()
    return {"recetas": [r.id for r in recetas]}

@app.post("/recetas/surtir/{receta_id}")
async def surtir_receta(
    receta_id: int,
    farmaceutico_id: int = Form(...),
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
    
    try:
        # Usa la clave AES almacenada (hex string)
        aes_key = bytes.fromhex(receta.clave_aes)
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.GCM(bytes.fromhex(receta.nonce), bytes.fromhex(receta.tag)),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        mensaje = decryptor.update(bytes.fromhex(receta.receta_cifrada)) + decryptor.finalize()
    except Exception as e:
        raise HTTPException(status_code=400, detail="Error al descifrar la receta: " + str(e))

    receta.estado = "surtida"
    receta.fecha_surtido = datetime.utcnow()
    receta.farmaceutico_id = farmaceutico_id
    db.commit()

    return {
        "message": "Receta surtida con éxito",
        "receta_id": receta.id,
        "contenido_receta": mensaje.decode("utf-8")
    }
@app.get("/usuario_info/")
async def usuario_info(username: str = Query(...), db: Session = Depends(get_db)):
    user = db.query(Usuario).filter(Usuario.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    if user.tipo_usuario == "paciente":
        paciente = db.query(Paciente).filter(Paciente.usuario_id == user.id).first()
        paciente_id = paciente.id if paciente else None
        return {
            "id_usuario": user.id,
            "id_tipo": paciente_id,
            "tipo_usuario": user.tipo_usuario,
            "username": user.username,
        }
    elif user.tipo_usuario == "medico":
        medico = db.query(Medico).filter(Medico.usuario_id == user.id).first()
        medico_id = medico.id if medico else None
        return {
            "id_usuario": user.id,
            "id_tipo": medico_id,
            "tipo_usuario": user.tipo_usuario,
            "username": user.username,
        }
    elif user.tipo_usuario == "farmaceutico":
        farmaceutico = db.query(Farmaceutico).filter(Farmaceutico.usuario_id == user.id).first()
        farmaceutico_id = farmaceutico.id if farmaceutico else None
        return {
            "id_usuario": user.id,
            "id_tipo": farmaceutico_id,
            "tipo_usuario": user.tipo_usuario,
            "username": user.username,
        }
    else:
        return {
            "id_usuario": user.id,
            "id_tipo": None,
            "tipo_usuario": user.tipo_usuario,
            "username": user.username,
        }
from fastapi import UploadFile, File, Form

@app.post("/recetas/contenido/{receta_id}")
async def obtener_contenido_receta(
    receta_id: int,
    usuario_id: int = Form(...),
    tipo_usuario: str = Form(...),  
    db: Session = Depends(get_db)
):
    receta = db.query(Receta).filter(Receta.id == receta_id).first()
    if not receta:
        raise HTTPException(status_code=404, detail="Receta no encontrada")
    try:
        # Cargar la clave privada RSA
        private_key = load_private_key()

        # Descifrar la clave AES (cifrada con RSA-OAEP) usando la clave privada
        encrypted_aes_key = base64.b64decode(receta.clave_aes)  # Clave AES cifrada en la base de datos
        aes_key = decrypt_aes_key_with_rsa(encrypted_aes_key, private_key)
        
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.GCM(bytes.fromhex(receta.nonce), bytes.fromhex(receta.tag)),
            backend=default_backend(),
        )
        decryptor = cipher.decryptor()
        mensaje = decryptor.update(bytes.fromhex(receta.receta_cifrada)) + decryptor.finalize()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error al descifrar el contenido: {e}")

    return {
        "receta_id": receta.id,
        "contenido_receta": mensaje.decode("utf-8"),
        "estado": receta.estado,
        "fecha_emision": receta.fecha_emision,
        "fecha_vencimiento": receta.fecha_vencimiento,
        "fecha_surtido": receta.fecha_surtido,
    }

