"""
Database Schemas for the SMB Operations App

Each Pydantic model maps to a MongoDB collection. The collection name is the
lowercased class name.

Relations (logical):
- users → projects → tasks (assignee references user._id)
- users → contacts → quotes (created_by references user._id)

These schemas are used for validation only. MongoDB remains schemaless, but we
use them to ensure data integrity at the API boundary.
"""
from __future__ import annotations

from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List, Literal
from datetime import date, datetime

# ---------- Core ----------

class Session(BaseModel):
    user_id: str
    token: str
    created_at: Optional[datetime] = None

class User(BaseModel):
    name: str = Field(..., description="Full name")
    email: EmailStr
    role: Literal["Admin", "Employee"] = "Employee"
    hashed_password: str
    is_active: bool = True

class Company(BaseModel):
    name: str
    domain: Optional[str] = None
    notes: Optional[str] = None

# ---------- CRM ----------

ContactStatus = Literal["Prospect", "Client", "Negotiation"]

class Interaction(BaseModel):
    type: Literal["email", "call", "note"]
    content: str
    date: datetime = Field(default_factory=datetime.utcnow)
    user_id: Optional[str] = None

class Contact(BaseModel):
    name: str
    email: Optional[EmailStr] = None
    phone: Optional[str] = None
    company_id: Optional[str] = None
    company_name: Optional[str] = None
    status: ContactStatus = "Prospect"
    notes: Optional[str] = None
    interactions: List[Interaction] = []
    created_by: Optional[str] = None

# ---------- Quotes ----------

QuoteStatus = Literal["Draft", "Sent", "Accepted", "Declined"]

class QuoteItem(BaseModel):
    name: str
    description: Optional[str] = None
    unit_price: float
    quantity: float = 1
    tax_rate: float = 0.0  # percent, e.g., 20 for 20%

class Quote(BaseModel):
    contact_id: Optional[str] = None
    company_id: Optional[str] = None
    company_name: Optional[str] = None
    items: List[QuoteItem]
    currency: str = "USD"
    status: QuoteStatus = "Draft"
    total: Optional[float] = None
    public_token: Optional[str] = None
    created_by: Optional[str] = None
    created_at: Optional[datetime] = None

# ---------- Projects & Tasks ----------

TaskStatus = Literal["To Do", "In Progress", "Completed"]
Priority = Literal["Low", "Medium", "High"]

class Project(BaseModel):
    name: str
    description: Optional[str] = None
    owner_id: Optional[str] = None

class Task(BaseModel):
    project_id: str
    title: str
    description: Optional[str] = None
    assignee_id: Optional[str] = None
    due_date: Optional[date] = None
    priority: Priority = "Medium"
    status: TaskStatus = "To Do"

# ---------- Settings ----------

class Settings(BaseModel):
    company_name: Optional[str] = None
    language: Optional[str] = "en"
    theme: Optional[str] = "light"
