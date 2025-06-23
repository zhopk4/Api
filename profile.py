from pydantic import BaseModel, Field, validator
from datetime import date
import re
from enum import Enum


class UserRole(str, Enum):
    admin = "admin"
    user = "user"

class UserProfile(BaseModel):
    id: int
    name: str
    surname: str
    patronymic: str
    group_name: str = Field(..., description="Group name in VARCHAR format")
    birthday: date
    email: str
    icon: str

    @validator('group_name')
    def validate_group_name(cls, value):
        # Пример валидации: проверка на соответствие шаблону "ИСП-421п"
        pattern = re.compile(r'^[А-ЯЁа-яёA-Za-z0-9\-\_ ]+-\d+[А-ЯЁа-яёA-Za-z0-9]*$')
        if not pattern.match(value):
            raise ValueError('Group name must be in format like "ИСП-421", "ABC-123A" or similar with Latin or Cyrillic letters, numbers and hyphens.')
        return value

    @validator('birthday')
    def validate_birthday(cls, value):
        # Пример валидации: проверка на корректность даты
        if value > date.today():
            raise ValueError('Birthday cannot be in the future')
        return value

    class Config:
        orm_mode = True

