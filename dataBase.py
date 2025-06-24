from sqlalchemy import create_engine, Column, Integer, String, Date, Time, ForeignKey, Text, Enum, DateTime
from sqlalchemy.dialects.postgresql import VARCHAR
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from datetime import datetime
import enum

# Конфигурация базы данных
DATABASE_URL = "postgresql://my_db_w9dy_user:bXQYcSzAoiVwaTk0IQrLLqKJMlg9Yt7m@dpg-d1cvo8buibrs73dm4rlg-a.frankfurt-postgres.render.com/my_db_w9dy"

# Создаем движок с настройками
engine = create_engine(
    DATABASE_URL,
    echo=True,  # Для отладки
    pool_size=5,
    max_overflow=10,
    pool_timeout=30,
    pool_recycle=3600
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class UserRole(enum.Enum):
    admin = "admin"
    user = "user"

class TaskStatus(enum.Enum):
    active = "active"
    completed = "completed"

class MessageStatus(enum.Enum):
    sent = "sent"
    delivered = "delivered"
    read = "read"

class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, nullable=False, autoincrement=True, index=True)
    name = Column(String(50), nullable=False)
    surname = Column(String(50), nullable=False)
    patronymic = Column(String(60), nullable=True)
    group_name = Column(VARCHAR(50), nullable=False)
    birthday = Column(Date, nullable=False)
    password = Column(String, nullable=False)
    login = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(70), unique=True, index=True, nullable=False)
    role = Column(Enum(UserRole), default=UserRole.user, nullable=False)

    tasks = relationship("Task", back_populates="creator", cascade="all, delete-orphan")
    events = relationship("Event", back_populates="user", cascade="all, delete-orphan")

class Event(Base):
    __tablename__ = 'events'

    id = Column(Integer, primary_key=True, nullable=False, autoincrement=True, index=True)
    nameEvent = Column(String(100), nullable=False)
    dataEvent = Column(Date, nullable=False)
    timeEvent = Column(Time, nullable=False)
    participants = Column(Integer, nullable=False)
    locationEvent = Column(String(150), nullable=False)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)

    user = relationship("User", back_populates="events")

class Task(Base):
    __tablename__ = "tasks"

    id = Column(Integer, primary_key=True, index=True)
    task = Column(String(255), nullable=False)
    task_description = Column(Text, nullable=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    status = Column(Enum(TaskStatus), default=TaskStatus.active, nullable=False)

    creator = relationship("User", back_populates="tasks")

class Message(Base):
    __tablename__ = 'messages'
    id = Column(Integer, primary_key=True, index=True)
    sender_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    receiver_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    message_text = Column(String(500), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    status = Column(Enum(MessageStatus), default=MessageStatus.sent, nullable=False)

    sender = relationship("User", foreign_keys=[sender_id], backref="sent_messages")
    receiver = relationship("User", foreign_keys=[receiver_id], backref="received_messages")

# Создание таблиц
Base.metadata.create_all(engine)
