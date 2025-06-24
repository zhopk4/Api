from enum import Enum
from pydantic import BaseModel, Field, validator, ConfigDict
from datetime import date, datetime, time
import re
from typing import Optional

class UserRole(str, Enum):
    admin = "admin"
    user = "user"

class TaskStatus(str, Enum):
    active = "active"
    completed = "completed"

class MessageStatus(str, Enum):
    sent = "sent"
    delivered = "delivered"
    read = "read"

class UserProfile(BaseModel):
    id: int
    name: str
    surname: str
    patronymic: Optional[str] = None
    group_name: str
    birthday: Optional[date] = None
    email: str
    role: str

class UserRegister(BaseModel):
    name: str
    surname: str
    patronymic: Optional[str] = None
    group_name: str = Field(..., description="Group name in VARCHAR format")
    birthday: date
    login: str
    email: str
    password: str

    @validator('group_name')
    def validate_group_name(cls, v):
        if v is None:
            raise ValueError('Group name is required')
        pattern = r'^[А-ЯЁ]{2,4}-\d{3}[а-яё]{0,3}$'
        if not re.fullmatch(pattern, v, flags=re.IGNORECASE):
            raise ValueError(
                'Номер группы должен быть в формате: '
                '2-4 заглавные русские буквы, дефис, 3 цифры '
                'и опционально 1-3 строчные буквы (например: ИСП-421, ДО-421п, ИСП-421ир)'
            )
        parts = v.split('-')
        if len(parts) == 2:
            parts[0] = parts[0].upper()
            parts[1] = parts[1][:3] + parts[1][3:].lower()
            return '-'.join(parts)
        return v

    @validator('birthday')
    def validate_birthday(cls, value):
        if value > date.today():
            raise ValueError('Дата рождения не может быть в будущем.')
        return value

    class Config:
        orm_mode = True
        json_encoders = {
            date: lambda v: v.isoformat() if v else None
        }

class UserLogin(BaseModel):
    login: str
    password: str

class RestorePasswordRequest(BaseModel):
    login: str
    new_password: str

class TokenData(BaseModel):
    sub: str

class UserProfileUpdate(BaseModel):
    name: Optional[str] = None
    surname: Optional[str] = None
    patronymic: Optional[str] = None
    group_name: Optional[str] = None
    birthday: Optional[date] = None
    email: Optional[str] = None

class UserRoleUpdate(BaseModel):
    user_id: int
    new_role: UserRole

class TaskCreate(BaseModel):
    task: str
    task_description: Optional[str] = None

class TaskUpdate(BaseModel):
    task: Optional[str] = None
    task_description: Optional[str] = None
    status: Optional[TaskStatus] = None

class TaskWithCreator(BaseModel):
    id: int
    task: str
    task_description: Optional[str] = None
    created_at: datetime
    status: str
    created_by: int
    creator_surname: str
    creator_name: str

    class Config:
        from_attributes = True

class TaskStats(BaseModel):
    total_tasks: int
    active_tasks: int
    completed_tasks: int

class MessageCreate(BaseModel):
    receiver_id: int
    message_text: str = Field(..., min_length=1, max_length=500)

class MessageResponse(BaseModel):
    id: int
    sender_id: int
    receiver_id: int
    message_text: str
    timestamp: datetime
    status: MessageStatus

    class Config:
        orm_mode = True

class PasswordVerification(BaseModel):
    password: str = Field(..., min_length=1, description="Пароль пользователя")

    class Config:
        json_schema_extra = {
            "example": {
                "password": "your_password"
            }
        }

class EventBase(BaseModel):
    name_event: str
    data_event: date
    time_event: str  # Формат "HH:MM"
    participants: int
    location_event: str

    @validator('time_event')
    def validate_time(cls, v):
        try:
            datetime.strptime(v, "%H:%M").time()
            return v
        except ValueError:
            raise ValueError('Неверный формат времени. Используйте HH:MM')

class EventCreate(EventBase):
    pass

class EventUpdate(BaseModel):
    name_event: Optional[str]
    data_event: Optional[date]
    time_event: Optional[str]
    participants: Optional[int]
    location_event: Optional[str]

class EventResponse(EventBase):
    id: int
    user_id: int
    creator_name: str
    creator_surname: str

    class Config:
        from_attributes = True
