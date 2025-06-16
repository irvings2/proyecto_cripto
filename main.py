from fastapi import FastAPI, Depends, HTTPException, File, UploadFile, Form
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, Boolean, ForeignKey, Text, TIMESTAMP
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from sqlalchemy import select
from pydantic import BaseModel
from passlib.context import CryptContext
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization
from io import BytesIO
from fastapi.responses import FileResponse
from typing import Union, Optional
from datetime import datetime
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

class Receta(Base):
    __tablename__ = 'receta'

    id = Column(Integer, primary_key=True, index=True)
    paciente_id = Column(Integer, ForeignKey('paciente.id'), nullable=False)
    medico_id = Column(Integer, ForeignKey('medico.id'), nullable=False)
    farmaceutico_id = Column(Integer, ForeignKey('farmaceutico.id'), nullable=True)
    fecha_emision = Column(TIMESTAMP, default=datetime.utcnow, nullable=False)
    fecha_vencimiento = Column(TIMESTAMP, nullable=False)
    estado = Column(String(50), nullable=False, default='emitida')
    firma_digital_medico = Column(Text, nullable=False)
    fecha_surtido = Column(TIMESTAMP, nullable=True)
    observaciones = Column(Text, nullable=True)
    receta = Column(Text, nullable=True)

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
    direccion: str
    farmacia_id: int  # Relación con la clínica

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
            direccion=usuario.direccion,
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
    
    # Verificar contraseña
    if not pwd_context.verify(password, user.password_hash):
        raise HTTPException(status_code=401, detail="Contraseña incorrecta")
    
    # Verificar si las llaves ya fueron generadas
    if user.llavesgeneradas:
        return {"username": user.username, "tipo_usuario": user.tipo_usuario}
    
    # Si no han sido generadas, creamos las llaves
    private_key_ed, public_key_ed = generate_ed25519_keys()
    
    # Generar las llaves X25519
    private_key_x255, public_key_x255 = generate_x25519_keys()  # Llamamos a la función que ya tienes implementada
    
    # Guardar la clave pública de ED25519 y X25519 en la base de datos
    user.public_key_ed = public_key_ed
    user.public_key_x255 = public_key_x255
    user.llavesgeneradas = True
    db.commit()

    # Guardar las claves privadas como archivos .pem para ser descargados
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
    
    # Guardar los archivos de las claves privadas en el servidor para permitir la descarga
    private_key_ed_file_path = f"private_key_ed_{username}.pem"
    private_key_x255_file_path = f"private_key_x255_{username}.pem"
    
    with open(private_key_ed_file_path, "wb") as f:
        f.write(private_key_ed_pem)
    
    with open(private_key_x255_file_path, "wb") as f:
        f.write(private_key_x255_pem)
    
    # Devolver los archivos de las claves privadas para ser descargados
    return {
        "username": user.username,
        "tipo_usuario": user.tipo_usuario,
        "public_key_ed": public_key_ed,
        "public_key_x255": public_key_x255,
        "private_key_ed_file": FileResponse(path=private_key_ed_file_path, filename=private_key_ed_file_path, media_type='application/pem'),
        "private_key_x255_file": FileResponse(path=private_key_x255_file_path, filename=private_key_x255_file_path, media_type='application/pem')
    }

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
        farmaceutico_id=farmaceutico_id,
        fecha_emision=datetime.utcnow(),  # Fecha actual de emisión
        fecha_vencimiento=datetime.fromisoformat(fecha_vencimiento),  # Convertir a datetime
        estado=estado,
        firma_digital_medico=signature.hex(),  # Guardamos la firma digital como hex
    )

    # Agregar la receta a la base de datos
    db.add(nueva_receta)
    db.commit()
    db.refresh(nueva_receta)

    # Retornar la firma y la receta con los datos básicos
    return {
        "message": "Receta firmada con éxito.",
        "firma_digital": signature.hex(),  # Devolver la firma digital como un string hexadecimal
        "receta_id": nueva_receta.id,
        "medico": medico.nombre,
        "paciente": paciente.nombre,
        "estado": nueva_receta.estado,
        "fecha_vencimiento": nueva_receta.fecha_vencimiento
    }
    
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
