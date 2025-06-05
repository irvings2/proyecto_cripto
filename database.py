from sqlalchemy import create_engine, Column, Integer, String, Enum, Text, TIMESTAMP, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy import DateTime
import mysql.connector
import datetime

# Configuración de la base de datos
DATABASE_URL = "mysql+mysqlconnector://root:12345678@localhost/proyectorecetas"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

# Modelo de Usuario
class Usuario(Base):
    __tablename__ = "Usuario"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(20), unique=True, index=True)
    password_hash = Column(String(255))
    tipo_usuario = Column(Enum('medico', 'paciente', 'farmaceutico'))
    public_key = Column(Text, nullable=True)
    llavesgeneradas = Column(Boolean, nullable=True)
    fecha_creacion = Column(TIMESTAMP(timezone=False),
                         default=datetime.datetime.now)

# Crear las tablas si no existen
def create_db():
    Base.metadata.create_all(bind=engine)
