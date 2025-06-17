from fastapi import FastAPI, Depends, HTTPException, File, UploadFile, Form
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, Boolean, ForeignKey, Text, TIMESTAMP
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from sqlalchemy import select
from pydantic import BaseModel
from passlib.context import CryptContext
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization
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
async def firmar_mensaje(
    paciente_id: int = Form(...),  # Recibimos los parámetros como Form (ya que multipart/form-data los manda así)
    medico_id: int = Form(...),
    farmaceutico_id: Optional[int] = Form(None),
    fecha_vencimiento: str = Form(...),  # La fecha de vencimiento
    estado: str = Form("emitida"),  # Estado con valor por defecto
    mensaje: str = Form(...),  # El mensaje a firmar
    private_key_file: UploadFile = File(...),  # Recibimos la clave privada como archivo
    db: Session = Depends(get_db)
):
    # Verificar si el paciente existe
    paciente = db.query(Paciente).filter(Paciente.id == paciente_id).first()
    if not paciente:
        raise HTTPException(status_code=404, detail="Paciente no encontrado")

    # Verificar si el médico existe
    medico = db.query(Medico).filter(Medico.id == medico_id).first()
    if not medico:
        raise HTTPException(status_code=404, detail="Médico no encontrado")
    
    # Asegurarse de que el usuario que firma es un médico y que las llaves están generadas
    if not medico.usuario.llavesgeneradas:
        raise HTTPException(status_code=400, detail="Las llaves no han sido generadas para este médico")

    # Leer la clave privada desde el archivo .pem
    private_key_pem = await private_key_file.read()
    try:
        private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    except Exception as e:
        raise HTTPException(status_code=400, detail="No se pudo cargar la clave privada del médico")

    # Firmar el mensaje usando la clave privada
    try:
        signature = private_key.sign(mensaje.encode())  # Firmar el mensaje con la clave privada
    except Exception as e:
        raise HTTPException(status_code=400, detail="Error al firmar el mensaje")

    # Crear la receta con los datos proporcionados
    nueva_receta = Receta(
        paciente_id=paciente_id,
        medico_id=medico_id,
        fecha_emision=datetime.utcnow(),  # Fecha actual de emisión
        fecha_vencimiento=datetime.fromisoformat(fecha_vencimiento),  # Convertir a datetime
        estado=estado,
    )

    # Agregar la receta a la base de datos
    db.add(nueva_receta)
    db.commit()
    db.refresh(nueva_receta)

    # Guardar mensaje y firma en un archivo .txt
    file_content = f"idreceta: {nueva_receta.id}\n\nMensaje: {mensaje}\n\nFirma Digital: {signature.hex()}"

    # Guardar archivo en el directorio temporal
    file_name = f"firma_{nueva_receta.id}.txt"
    file_path = os.path.join(TEMP_DIR, file_name)

    with open(file_path, "w") as file:
        file.write(file_content)

    # Retornar la respuesta con la URL para descargar el archivo generado
    return {
        "message": "Receta firmada con éxito.",
        "firma_digital": signature.hex(),  # Devolver la firma digital como un string hexadecimal
        "receta_id": nueva_receta.id,
        "medico": medico.nombre,
        "paciente": paciente.nombre,
        "estado": nueva_receta.estado,
        "fecha_vencimiento": nueva_receta.fecha_vencimiento,
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

    # Verificar la firma usando la clave pública del médico
    try:
        public_key.verify(
            firma,
            mensaje.encode(),  # Convertimos el mensaje a bytes
            padding.PKCS1v15(),
            hashes.SHA256()
        )
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
