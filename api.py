import json
from typing import List, Optional
from urllib.request import Request

from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File, Query, APIRouter
from fastapi.exceptions import RequestValidationError
from fastapi.security import OAuth2PasswordBearer
from fastapi.responses import Response
from passlib.context import CryptContext
from sqlalchemy import or_
from sqlalchemy.orm import Session, joinedload

from datetime import datetime, timedelta, date
from functools import wraps
from jwt import decode as jwt_decode, encode as jwt_encode, PyJWTError
from starlette.responses import JSONResponse

from dataBase import (User, Task, UserRole, TaskStatus, SessionLocal, Message, MessageStatus, Event)
from schemas import (UserProfile, UserRegister, UserLogin, UserProfileUpdate, UserRoleUpdate, TaskCreate, TaskUpdate,
                     TaskWithCreator, TaskStats, RestorePasswordRequest, MessageCreate, MessageResponse,
                     PasswordVerification, EventResponse, EventUpdate, EventCreate)
import logging
import random
from dotenv import load_dotenv
import os
import re

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY", "default-secret-key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 10080

# Контекст хэширования паролей
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Инициализация приложения
app = FastAPI()

router = APIRouter(prefix="/events")
app.include_router(router)

# Логирование
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Подключение к базе данных
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def authenticate_user(db: Session, login: str, password: str) -> Optional[User]:
    user = db.query(User).filter(User.login == login).first()
    if not user or not verify_password(password, user.password):
        return None
    return user

def create_access_token(data: dict, expires_delta: timedelta = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    return jwt_encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt_decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception

        # Проверка срока действия токена
        expire = payload.get("exp")
        if expire is None or datetime.utcnow() > datetime.utcfromtimestamp(expire):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token expired",
                headers={"WWW-Authenticate": "Bearer"},
            )

        user = db.query(User).filter(User.id == user_id).first()
        if user is None:
            raise credentials_exception
        return user
    except PyJWTError:
        raise credentials_exception

def role_required(required_role: UserRole):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            current_user = kwargs.get('current_user')
            if current_user.role != required_role:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Operation not permitted"
                )
            return await func(*args, **kwargs)
        return wrapper
    return decorator

def check_event_permissions(db: Session, event_id: int, current_user: User):
    db_event = db.query(Event).filter(Event.id == event_id).first()
    if not db_event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Event not found"
        )
    if db_event.user_id != current_user.id and current_user.role != UserRole.admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have permission to modify this event"
        )
    return db_event

@app.get("/")
async def read_root():
    return {"message": "Welcome to the API"}

@app.middleware("http")
async def errors_middleware(request: Request, call_next):
    try:
        return await call_next(request)
    except Exception as e:
        logger.error(f"Ошибка: {str(e)}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"detail": "Внутренняя ошибка сервера"}
        )

@app.post("/login")
async def login(user_login: UserLogin, db: Session = Depends(get_db)):
    user = authenticate_user(db, user_login.login, user_login.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={
            "sub": str(user.id),
            "role": user.role.value,
            "login": user.login,
            "email": user.email
        },
        expires_delta=access_token_expires
    )
    return {
        "name": user.name,
        "surname": user.surname,
        "access_token": access_token,
        "token_type": "bearer",
        "user_id": user.id,
        "role": user.role.value,
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    }

@app.get("/auth/verify")
async def validate_token(current_user: User = Depends(get_current_user)):
    return {
        "valid": True,
        "user_id": current_user.id,
        "role": current_user.role.value,
        "login": current_user.login,
        "email": current_user.email
    }

@app.post("/register", response_model=UserProfile, status_code=201)
async def register(user_register: UserRegister, db: Session = Depends(get_db)):
    try:
        # Проверка существования пользователя
        existing_user = db.query(User).filter(
            or_(
                User.login == user_register.login,
                User.email == user_register.email
            )
        ).first()
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User with this login or email already exists"
            )

        # Валидация группы
        if user_register.group_name:
            if not re.fullmatch(r'^[А-ЯЁ]{2,4}-\d{3}[а-яё]{0,3}$', user_register.group_name):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail='Group name must be in format: 2-4 uppercase Russian letters, hyphen, 3 digits and optional 1-3 lowercase letters'
                )

        # Хэширование пароля
        hashed_password = get_password_hash(user_register.password)

        # Создание пользователя
        db_user = User(
            name=user_register.name,
            surname=user_register.surname,
            patronymic=user_register.patronymic,
            group_name=user_register.group_name,
            birthday=user_register.birthday,
            password=hashed_password,
            login=user_register.login,
            email=user_register.email,
            role=UserRole.user
        )
        db.add(db_user)
        db.commit()
        db.refresh(db_user)

        return UserProfile(
            id=db_user.id,
            name=db_user.name,
            surname=db_user.surname,
            patronymic=db_user.patronymic,
            group_name=db_user.group_name,
            birthday=db_user.birthday,
            email=db_user.email,
            role=db_user.role.value
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error during user registration: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during registration"
        )

@app.get("/users/profile", response_model=UserProfile)
async def read_user_profile(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        user = db.query(User).filter(User.id == current_user.id).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        return UserProfile(
            id=user.id,
            name=user.name,
            surname=user.surname,
            patronymic=user.patronymic,
            group_name=user.group_name,
            birthday=user.birthday,
            email=user.email,
            role=user.role.value
        )
    except Exception as e:
        logger.error(f"Error getting user profile: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error getting user profile"
        )

@app.put("/users/profile", response_model=UserProfile)
async def update_user_profile(
    profile_update: UserProfileUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    try:
        user = db.query(User).filter(User.id == current_user.id).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        update_data = profile_update.dict(exclude_unset=True)

        # Проверяем, что группа не пустая, если она передается
        if 'group_name' in update_data and (update_data['group_name'] is None or update_data['group_name'].strip() == ''):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Group name cannot be empty"
            )

        for field, value in update_data.items():
            setattr(user, field, value)

        db.commit()
        db.refresh(user)

        return UserProfile(
            id=user.id,
            name=user.name,
            surname=user.surname,
            patronymic=user.patronymic,
            group_name=user.group_name,
            birthday=user.birthday,
            email=user.email,
            role=user.role.value
        )
    except Exception as e:
        logger.error(f"Error updating user profile: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error updating user profile"
        )

@app.post("/users/verify-password")
async def verify_user_password(
    password_verification: PasswordVerification,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    try:
        user = db.query(User).filter(User.id == current_user.id).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        return {"valid": verify_password(password_verification.password, user.password)}
    except Exception as e:
        logger.error(f"Error verifying password: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error verifying password"
        )

@app.get("/users/all", response_model=List[UserProfile])
async def get_all_users(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    try:
        users = db.query(User).all()
        return [
            UserProfile(
                id=user.id,
                name=user.name,
                surname=user.surname,
                patronymic=user.patronymic,
                group_name=user.group_name,
                birthday=user.birthday,
                email=user.email,
                role=user.role.value
            )
            for user in users
        ]
    except Exception as e:
        logger.error(f"Error getting all users: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error getting all users"
        )

@app.get("/users/{user_id}", response_model=UserProfile)
async def read_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if current_user.role != UserRole.admin and current_user.id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only view your own profile unless you're an admin"
        )
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        return UserProfile(
            id=user.id,
            name=user.name,
            surname=user.surname,
            patronymic=user.patronymic,
            group_name=user.group_name,
            birthday=user.birthday,
            email=user.email,
            role=user.role.value
        )
    except Exception as e:
        logger.error(f"Error getting user: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error getting user"
        )

@app.put("/users/role")
@role_required(UserRole.admin)
async def update_user_role(
    role_update: UserRoleUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    try:
        user = db.query(User).filter(User.id == role_update.user_id).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        user.role = role_update.new_role
        db.commit()
        db.refresh(user)
        return {"message": "User role updated successfully"}
    except Exception as e:
        logger.error(f"Error updating user role: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error updating user role"
        )

@app.post("/restore-password")
async def restore_password(
    restore_request: RestorePasswordRequest,
    db: Session = Depends(get_db)
):
    try:
        user = db.query(User).filter(User.login == restore_request.login).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        hashed_password = get_password_hash(restore_request.new_password)
        user.password = hashed_password
        db.commit()
        return {"message": "Password restored successfully"}
    except Exception as e:
        logger.error(f"Error restoring password: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error restoring password"
        )

@app.get("/tasks/", response_model=List[TaskWithCreator])
async def read_tasks(
    skip: int = 0,
    limit: int = 10,
    sort_by: Optional[str] = None,
    status: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    try:
        query = db.query(Task).options(joinedload(Task.creator))
        if status is not None:
            try:
                task_status = TaskStatus(status)
                query = query.filter(Task.status == task_status)
            except ValueError:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid status. Allowed values: {[s.value for s in TaskStatus]}"
                )
        valid_sort_fields = ["created_at", "task", "status"]
        if sort_by and sort_by in valid_sort_fields:
            if sort_by == "created_at":
                query = query.order_by(Task.created_at.desc())
            elif sort_by == "task":
                query = query.order_by(Task.task)
            elif sort_by == "status":
                query = query.order_by(Task.status)
        else:
            query = query.order_by(Task.created_at.desc())

        tasks = query.offset(skip).limit(limit).all()
        return [
            TaskWithCreator(
                id=task.id,
                task=task.task,
                task_description=task.task_description or "",
                created_at=task.created_at,
                status=task.status.value,
                created_by=task.created_by,
                creator_surname=task.creator.surname if task.creator else "Unknown",
                creator_name=task.creator.name if task.creator else "Unknown",
            )
            for task in tasks
        ]
    except Exception as e:
        logger.error(f"Error getting tasks: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error getting tasks"
        )

@app.post("/tasks/", response_model=TaskWithCreator)
@role_required(UserRole.admin)
async def create_task(
    task: TaskCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    try:
        db_task = Task(
            task=task.task,
            task_description=task.task_description or "",
            created_by=current_user.id,
            created_at=datetime.utcnow(),
            status=TaskStatus.active
        )
        db.add(db_task)
        db.commit()
        db.refresh(db_task)

        creator = db.query(User).filter(User.id == current_user.id).first()
        return TaskWithCreator(
            id=db_task.id,
            task=db_task.task,
            task_description=db_task.task_description or "",
            created_at=db_task.created_at,
            status=db_task.status.value,
            created_by=db_task.created_by,
            creator_surname=creator.surname if creator else "Unknown",
            creator_name=creator.name if creator else "Unknown",
        )
    except Exception as e:
        logger.error(f"Error creating task: {str(e)}", exc_info=True)
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error creating task"
        )

@app.put("/tasks/{task_id}", response_model=TaskWithCreator)
@role_required(UserRole.admin)
async def update_task(
    task_id: int,
    task_update: TaskUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    try:
        db_task = db.query(Task).options(joinedload(Task.creator)).filter(Task.id == task_id).first()
        if not db_task:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Task not found"
            )

        # Обновление статуса
        if task_update.status is not None:
            try:
                db_task.status = TaskStatus(task_update.status)
            except ValueError:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid status. Allowed values: {[s.value for s in TaskStatus]}"
                )

        # Обновление остальных полей
        update_data = task_update.dict(exclude_unset=True, exclude={"status"})
        for field, value in update_data.items():
            setattr(db_task, field, value)

        db.commit()
        db.refresh(db_task)

        creator = db.query(User).filter(User.id == db_task.created_by).first()
        return TaskWithCreator(
            id=db_task.id,
            task=db_task.task,
            task_description=db_task.task_description or "",
            created_at=db_task.created_at,
            status=db_task.status.value,
            created_by=db_task.created_by,
            creator_surname=creator.surname if creator else "Unknown",
            creator_name=creator.name if creator else "Unknown",
        )
    except Exception as e:
        logger.error(f"Error updating task: {str(e)}", exc_info=True)
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error updating task"
        )

@app.delete("/tasks/{task_id}", response_model=TaskWithCreator)
@role_required(UserRole.admin)
async def delete_task(
    task_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    try:
        db_task = db.query(Task).options(joinedload(Task.creator)).filter(Task.id == task_id).first()
        if not db_task:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Task not found"
            )

        creator = db.query(User).filter(User.id == db_task.created_by).first()
        result = TaskWithCreator(
            id=db_task.id,
            task=db_task.task,
            task_description=db_task.task_description or "",
            created_at=db_task.created_at,
            status=db_task.status.value,
            created_by=db_task.created_by,
            creator_surname=creator.surname if creator else "Unknown",
            creator_name=creator.name if creator else "Unknown",
        )

        db.delete(db_task)
        db.commit()
        return result
    except Exception as e:
        logger.error(f"Error deleting task: {str(e)}", exc_info=True)
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error deleting task"
        )

@app.get("/tasks/stats", response_model=TaskStats)
async def get_task_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    try:
        if current_user.role == UserRole.admin:
            total_tasks = db.query(Task).count()
            active_tasks = db.query(Task).filter(Task.status == TaskStatus.active).count()
            completed_tasks = db.query(Task).filter(Task.status == TaskStatus.completed).count()
        else:
            total_tasks = db.query(Task).filter(Task.created_by == current_user.id).count()
            active_tasks = db.query(Task).filter(
                (Task.created_by == current_user.id) &
                (Task.status == TaskStatus.active)
            ).count()
            completed_tasks = db.query(Task).filter(
                (Task.created_by == current_user.id) &
                (Task.status == TaskStatus.completed)
            ).count()

        return TaskStats(
            total_tasks=total_tasks,
            active_tasks=active_tasks,
            completed_tasks=completed_tasks
        )
    except Exception as e:
        logger.error(f"Error getting task stats: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error getting task stats"
        )

@app.get("/users/{user_id}/tasks", response_model=List[TaskWithCreator])
async def read_user_tasks(
    user_id: int,
    skip: int = 0,
    limit: int = 10,
    sort_by: Optional[str] = None,
    status: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    try:
        query = db.query(Task).options(joinedload(Task.creator)).filter(Task.created_by == user_id)

        if status is not None:
            try:
                task_status = TaskStatus(status)
                query = query.filter(Task.status == task_status)
            except ValueError:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid status. Allowed values: {[s.value for s in TaskStatus]}"
                )

        valid_sort_fields = ["created_at", "task", "status"]
        if sort_by and sort_by in valid_sort_fields:
            if sort_by == "created_at":
                query = query.order_by(Task.created_at.desc())
            elif sort_by == "task":
                query = query.order_by(Task.task)
            elif sort_by == "status":
                query = query.order_by(Task.status)
        else:
            query = query.order_by(Task.created_at.desc())

        tasks = query.offset(skip).limit(limit).all()
        return [
            TaskWithCreator(
                id=task.id,
                task=task.task,
                task_description=task.task_description or "",
                created_at=task.created_at,
                status=task.status.value,
                created_by=task.created_by,
                creator_surname=task.creator.surname if task.creator else "Unknown",
                creator_name=task.creator.name if task.creator else "Unknown",
            )
            for task in tasks
        ]
    except Exception as e:
        logger.error(f"Error getting user tasks: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error getting user tasks"
        )

@app.post("/messages/", response_model=MessageResponse)
async def create_message(
    message: MessageCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    try:
        db_message = Message(
            sender_id=current_user.id,
            receiver_id=message.receiver_id,
            message_text=message.message_text,
            timestamp=datetime.utcnow(),
            status=MessageStatus.sent
        )
        db.add(db_message)
        db.commit()
        db.refresh(db_message)
        return db_message
    except Exception as e:
        logger.error(f"Error creating message: {str(e)}", exc_info=True)
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error creating message"
        )

@app.get("/messages/", response_model=List[MessageResponse])
async def read_messages(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    try:
        messages = db.query(Message).offset(skip).limit(limit).all()
        return messages
    except Exception as e:
        logger.error(f"Error getting messages: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error getting messages"
        )


@app.delete("/messages/{message_id}", response_model=MessageResponse)
async def delete_message(
        message_id: int,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    try:
        db_message = db.query(Message).filter(Message.id == message_id).first()
        if not db_message:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Message not found"
            )
        if db_message.sender_id != current_user.id and current_user.role != UserRole.admin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You can only delete your own messages unless you're an admin"
            )

        # Создаем response перед удалением
        response_data = MessageResponse(
            id=db_message.id,
            sender_id=db_message.sender_id,
            message_text=db_message.message_text,
            timestamp=db_message.timestamp,
            status=db_message.status.value  # Преобразуем enum в строку
        )

        db.delete(db_message)
        db.commit()
        return response_data  # Возвращаем корректный Pydantic объект
    except Exception as e:
        logger.error(f"Error deleting message: {str(e)}", exc_info=True)
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error deleting message"
        )

@app.put("/messages/{message_id}/status")
async def update_message_status(
        message_id: int,
        new_status: MessageStatus,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    db_message = db.query(Message).filter(Message.id == message_id).first()
    if not db_message:
        raise HTTPException(status_code=404, detail="Message not found")
    db_message.status = new_status
    db.commit()
    return db_message


@app.post("/events/", response_model=EventResponse, status_code=201)
async def create_event(
        event: EventCreate,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    """ Создает новое событие. """
    try:
        # Проверяем дату на будущее
        if event.dataEvent < date.today():
            raise HTTPException(status_code=400, detail="Event date cannot be in the past")

        # Проверяем количество участников
        if event.participants <= 0:
            raise HTTPException(status_code=400, detail="Participants count must be positive")

        # Парсим время
        try:
            event_time = datetime.strptime(event.timeEvent, "%H:%M").time()
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid time format. Use HH:MM")

        # Создаем объект события
        db_event = Event(
            nameEvent=event.nameEvent,
            dataEvent=event.dataEvent,
            timeEvent=event_time,
            participants=event.participants,
            locationEvent=event.locationEvent,
            user_id=current_user.id
        )
        db.add(db_event)
        db.commit()
        db.refresh(db_event)

        # Возвращаем данные с информацией о создателе
        creator = db.query(User).filter(User.id == current_user.id).first()
        return EventResponse(
            id=db_event.id,
            nameEvent=db_event.nameEvent,
            dataEvent=db_event.dataEvent,
            timeEvent=db_event.timeEvent.strftime("%H:%M"),
            participants=db_event.participants,
            locationEvent=db_event.locationEvent,
            user_id=db_event.user_id,
            creator_name=creator.name,
            creator_surname=creator.surname,
        )
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error creating event: {str(e)}")
        db.rollback()
        raise HTTPException(status_code=500, detail="Internal server error")


@app.get("/events/", response_model=List[EventResponse])
async def read_events(
        date_from: Optional[date] = None,
        date_to: Optional[date] = None,
        user_id: Optional[int] = None,
        sort_by: Optional[str] = None,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    """ Получает список событий с фильтрами и сортировкой. """
    try:
        query = db.query(Event).options(joinedload(Event.user))

        # Применяем фильтры по дате
        if date_from:
            query = query.filter(Event.dataEvent >= date_from)
        if date_to:
            query = query.filter(Event.dataEvent <= date_to)

        # Применяем фильтр по пользователю
        if user_id is not None:
            if current_user.id != user_id and current_user.role != UserRole.admin:
                raise HTTPException(status_code=403, detail="Forbidden to access other users' events")
            query = query.filter(Event.user_id == user_id)

        # Применяем сортировку
        valid_sort_fields = ["dataEvent", "timeEvent", "nameEvent"]
        if sort_by and sort_by in valid_sort_fields:
            query = query.order_by(getattr(Event, sort_by))
        else:
            query = query.order_by(Event.dataEvent, Event.timeEvent)

        events = query.all()

        return [
            EventResponse(
                id=event.id,
                name_event=event.nameEvent,
                data_event=event.dataEvent,
                time_event=event.timeEvent.strftime("%H:%M"),
                participants=event.participants,
                location_event=event.locationEvent,
                user_id=event.user_id,
                creator_name=event.user.name,
                creator_surname=event.user.surname,
            ) for event in events
        ]
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error reading events: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/events/{event_id}", response_model=EventResponse)
async def read_event(
        event_id: int,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    """ Получает одно событие по его ID. """
    try:
        event = db.query(Event).options(joinedload(Event.user)).filter(Event.id == event_id).first()
        if not event:
            raise HTTPException(status_code=404, detail="Event not found")

        # Проверьте права текущего пользователя
        if event.user_id != current_user.id and current_user.role != UserRole.admin:
            raise HTTPException(status_code=403, detail="Forbidden to access this event")

        return EventResponse(
            id=event.id,
            name_event=event.nameEvent,
            data_event=event.dataEvent,
            time_event=event.timeEvent.strftime("%H:%M"),
            participants=event.participants,
            location_event=event.locationEvent,
            user_id=event.user_id,
            creator_name=event.user.name,
            creator_surname=event.user.surname,
        )
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error reading event: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")


@app.put("/events/{event_id}", response_model=EventResponse)
async def update_event(
        event_id: int,
        event_update: EventUpdate,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    """ Обновляет существующий элемент. """
    try:
        # Найдем событие и проверим права
        db_event = db.query(Event).filter(Event.id == event_id).first()
        if not db_event or (db_event.user_id != current_user.id and current_user.role != UserRole.admin):
            raise HTTPException(status_code=403, detail="Access denied")

        # Обновление полей
        updated_data = event_update.dict(exclude_unset=True)
        if 'dataEvent' in updated_data and updated_data['dataEvent'] < date.today():
            raise HTTPException(status_code=400, detail="Event date cannot be in the past")

        if 'timeEvent' in updated_data:
            try:
                event_time = datetime.strptime(updated_data['timeEvent'], "%H:%M").time()
                updated_data['timeEvent'] = event_time
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid time format. Use HH:MM")

        if 'participants' in updated_data and updated_data['participants'] <= 0:
            raise HTTPException(status_code=400, detail="Participants count must be positive")

        # Применяем изменения
        for key, value in updated_data.items():
            setattr(db_event, key, value)

        db.commit()
        db.refresh(db_event)

        # Возвращаем событие с информацией о создателе
        creator = db.query(User).filter(User.id == db_event.user_id).first()
        return EventResponse(
            id=db_event.id,
            nameEvent=db_event.nameEvent,
            dataEvent=db_event.dataEvent,
            timeEvent=db_event.timeEvent.strftime("%H:%M"),
            participants=db_event.participants,
            locationEvent=db_event.locationEvent,
            user_id=db_event.user_id,
            creator_name=creator.name,
            creator_surname=creator.surname,
        )
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error updating event: {str(e)}")
        db.rollback()
        raise HTTPException(status_code=500, detail="Internal server error")


@app.delete("/events/{event_id}")
async def delete_event(
        event_id: int,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    """ Удаляет событие по его ID. """
    try:
        # Проверяем наличие события и права доступа
        db_event = db.query(Event).filter(Event.id == event_id).first()
        if not db_event or (db_event.user_id != current_user.id and current_user.role != UserRole.admin):
            raise HTTPException(status_code=403, detail="Access denied")

        # Убираем событие
        db.delete(db_event)
        db.commit()
        return {"message": f"Event with ID {event_id} deleted successfully"}
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error deleting event: {str(e)}")
        db.rollback()
        raise HTTPException(status_code=500, detail="Internal server error")

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    error_data = {
        "detail": exc.errors(),
        "body": await request.body(),
        "headers": dict(request.headers),
        "query_params": dict(request.query_params),
        "path_params": dict(request.path_params),
        "url": str(request.url),
        "method": request.method
    }

    logger.error(f"Validation error for request: {json.dumps(error_data, indent=2, default=str)}")

    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": exc.errors(), "context": error_data},
    )
