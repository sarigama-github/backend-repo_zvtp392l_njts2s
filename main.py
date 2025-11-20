import os
import io
import csv
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Literal, Dict, Any

from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, HTMLResponse
from pydantic import BaseModel, EmailStr
from bson import ObjectId

from database import db, create_document, get_documents
from schemas import User as UserSchema, Company as CompanySchema, Contact as ContactSchema, Interaction as InteractionSchema, Quote as QuoteSchema, QuoteItem, Project as ProjectSchema, Task as TaskSchema, Settings as SettingsSchema

# FastAPI app
app = FastAPI(title="SMB Operations API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- Utilities ----------

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


class AuthUser(BaseModel):
    _id: str
    name: str
    email: EmailStr
    role: Literal["Admin", "Employee"]


def get_collection(name: str):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    return db[name]


def objid(id_str: str) -> ObjectId:
    try:
        return ObjectId(id_str)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid id")


# ---------- Auth ----------

class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str
    role: Literal["Admin", "Employee"] = "Admin"


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    token: str
    user: AuthUser


def get_current_user(token: str = Query(None, alias="token")) -> AuthUser:
    if not token:
        raise HTTPException(status_code=401, detail="Missing token")
    session = get_collection("session").find_one({"token": token})
    if not session:
        raise HTTPException(status_code=401, detail="Invalid token")
    user_doc = get_collection("user").find_one({"_id": session["user_id"]})
    if not user_doc:
        raise HTTPException(status_code=401, detail="Invalid session user")
    return AuthUser(_id=str(user_doc["_id"]), name=user_doc["name"], email=user_doc["email"], role=user_doc.get("role", "Employee"))


@app.post("/auth/register", response_model=TokenResponse)
def register(req: RegisterRequest):
    users = get_collection("user")
    if users.find_one({"email": req.email}):
        raise HTTPException(status_code=400, detail="Email already registered")
    user = {
        "name": req.name,
        "email": req.email,
        "role": req.role,
        "hashed_password": hash_password(req.password),
        "is_active": True,
        "created_at": datetime.now(timezone.utc),
    }
    user_id = users.insert_one(user).inserted_id
    token = secrets.token_urlsafe(24)
    get_collection("session").insert_one({
        "user_id": user_id,
        "token": token,
        "created_at": datetime.now(timezone.utc)
    })
    return TokenResponse(token=token, user=AuthUser(_id=str(user_id), name=user["name"], email=user["email"], role=user["role"]))


@app.post("/auth/login", response_model=TokenResponse)
def login(req: LoginRequest):
    users = get_collection("user")
    user = users.find_one({"email": req.email})
    if not user or user.get("hashed_password") != hash_password(req.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = secrets.token_urlsafe(24)
    get_collection("session").insert_one({
        "user_id": user["_id"],
        "token": token,
        "created_at": datetime.now(timezone.utc)
    })
    return TokenResponse(token=token, user=AuthUser(_id=str(user["_id"]), name=user["name"], email=user["email"], role=user.get("role", "Employee")))


@app.get("/auth/me", response_model=AuthUser)
def me(user: AuthUser = Depends(get_current_user)):
    return user


# ---------- CRM: Companies ----------

@app.post("/crm/companies")
def create_company(company: CompanySchema, user: AuthUser = Depends(get_current_user)):
    data = company.model_dump()
    data.update({"created_by": ObjectId(user._id), "created_at": datetime.now(timezone.utc)})
    _id = get_collection("company").insert_one(data).inserted_id
    return {"_id": str(_id), **company.model_dump()}


@app.get("/crm/companies")
def list_companies(q: Optional[str] = None, limit: int = 100, user: AuthUser = Depends(get_current_user)):
    query: Dict[str, Any] = {}
    if q:
        query["name"] = {"$regex": q, "$options": "i"}
    docs = get_collection("company").find(query).limit(limit)
    return [{"_id": str(d["_id"]), "name": d.get("name"), "domain": d.get("domain"), "notes": d.get("notes")} for d in docs]


@app.put("/crm/companies/{company_id}")
def update_company(company_id: str, company: CompanySchema, user: AuthUser = Depends(get_current_user)):
    res = get_collection("company").update_one({"_id": objid(company_id)}, {"$set": company.model_dump()})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Company not found")
    return {"_id": company_id, **company.model_dump()}


@app.delete("/crm/companies/{company_id}")
def delete_company(company_id: str, user: AuthUser = Depends(get_current_user)):
    get_collection("company").delete_one({"_id": objid(company_id)})
    return {"ok": True}


# ---------- CRM: Contacts ----------

@app.post("/crm/contacts")
def create_contact(contact: ContactSchema, user: AuthUser = Depends(get_current_user)):
    data = contact.model_dump()
    data.update({"created_by": ObjectId(user._id), "created_at": datetime.now(timezone.utc)})
    _id = get_collection("contact").insert_one(data).inserted_id
    return {"_id": str(_id), **contact.model_dump()}


@app.get("/crm/contacts")
def list_contacts(status: Optional[str] = None, q: Optional[str] = None, limit: int = 100, user: AuthUser = Depends(get_current_user)):
    query: Dict[str, Any] = {}
    if status:
        query["status"] = status
    if q:
        query["name"] = {"$regex": q, "$options": "i"}
    docs = get_collection("contact").find(query).limit(limit)
    res = []
    for d in docs:
        d["_id"] = str(d["_id"])
        res.append(d)
    return res


@app.put("/crm/contacts/{contact_id}")
def update_contact(contact_id: str, contact: ContactSchema, user: AuthUser = Depends(get_current_user)):
    res = get_collection("contact").update_one({"_id": objid(contact_id)}, {"$set": contact.model_dump(), "$currentDate": {"updated_at": True}})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Contact not found")
    return {"_id": contact_id, **contact.model_dump()}


@app.delete("/crm/contacts/{contact_id}")
def delete_contact(contact_id: str, user: AuthUser = Depends(get_current_user)):
    get_collection("contact").delete_one({"_id": objid(contact_id)})
    return {"ok": True}


@app.post("/crm/contacts/import")
async def import_contacts(file: UploadFile = File(...), user: AuthUser = Depends(get_current_user)):
    content = await file.read()
    text = content.decode("utf-8")
    reader = csv.DictReader(io.StringIO(text))
    inserted = 0
    for row in reader:
        contact = {
            "name": row.get("name") or row.get("Name"),
            "email": row.get("email") or row.get("Email"),
            "phone": row.get("phone") or row.get("Phone"),
            "company_name": row.get("company") or row.get("Company"),
            "status": row.get("status") or "Prospect",
            "notes": row.get("notes") or None,
            "interactions": [],
            "created_by": ObjectId(user._id),
            "created_at": datetime.now(timezone.utc)
        }
        if contact["name"]:
            get_collection("contact").insert_one(contact)
            inserted += 1
    return {"inserted": inserted}


@app.get("/crm/contacts/export")
def export_contacts(user: AuthUser = Depends(get_current_user)):
    docs = get_collection("contact").find({})
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["name", "email", "phone", "company", "status", "notes"])
    for d in docs:
        writer.writerow([
            d.get("name", ""), d.get("email", ""), d.get("phone", ""), d.get("company_name", ""), d.get("status", ""), d.get("notes", "")
        ])
    output.seek(0)
    return StreamingResponse(iter([output.getvalue()]), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=contacts.csv"})


@app.post("/crm/contacts/{contact_id}/interactions")
def add_interaction(contact_id: str, interaction: InteractionSchema, user: AuthUser = Depends(get_current_user)):
    data = interaction.model_dump()
    data["user_id"] = user._id
    res = get_collection("contact").update_one({"_id": objid(contact_id)}, {"$push": {"interactions": data}})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Contact not found")
    return {"ok": True}


# ---------- Quotes ----------

FREE_QUOTES_PER_MONTH = 5


def compute_quote_total(items: List[QuoteItem]) -> float:
    subtotal = sum(i.unit_price * i.quantity for i in items)
    tax = sum((i.unit_price * i.quantity) * (i.tax_rate / 100.0) for i in items)
    return round(subtotal + tax, 2)


@app.post("/quotes")
def create_quote(quote: QuoteSchema, user: AuthUser = Depends(get_current_user)):
    now = datetime.now(timezone.utc)
    start_month = datetime(now.year, now.month, 1, tzinfo=timezone.utc)
    count = get_collection("quote").count_documents({"created_by": ObjectId(user._id), "created_at": {"$gte": start_month}})
    if count >= FREE_QUOTES_PER_MONTH:
        raise HTTPException(status_code=402, detail="Free tier limit reached: max 5 quotes this month")
    data = quote.model_dump()
    data["total"] = compute_quote_total(quote.items)
    data["created_by"] = ObjectId(user._id)
    data["created_at"] = now
    data["public_token"] = secrets.token_urlsafe(16)
    _id = get_collection("quote").insert_one(data).inserted_id
    return {"_id": str(_id), **{k: v for k, v in data.items() if k != "_id"}}


@app.get("/quotes")
def list_quotes(status: Optional[str] = None, q: Optional[str] = None, user: AuthUser = Depends(get_current_user)):
    query: Dict[str, Any] = {"created_by": ObjectId(user._id)}
    if status:
        query["status"] = status
    docs = get_collection("quote").find(query).sort("created_at", -1)
    res = []
    for d in docs:
        d["_id"] = str(d["_id"]) ; d["created_by"] = str(d.get("created_by", ""))
        res.append(d)
    return res


@app.put("/quotes/{quote_id}")
def update_quote(quote_id: str, quote: QuoteSchema, user: AuthUser = Depends(get_current_user)):
    data = quote.model_dump()
    data["total"] = compute_quote_total(quote.items)
    res = get_collection("quote").update_one({"_id": objid(quote_id), "created_by": ObjectId(user._id)}, {"$set": data})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Quote not found")
    return {"_id": quote_id, **data}


@app.delete("/quotes/{quote_id}")
def delete_quote(quote_id: str, user: AuthUser = Depends(get_current_user)):
    get_collection("quote").delete_one({"_id": objid(quote_id), "created_by": ObjectId(user._id)})
    return {"ok": True}


@app.get("/public/quote/{token}", response_class=HTMLResponse)
def public_quote(token: str):
    d = get_collection("quote").find_one({"public_token": token})
    if not d:
        raise HTTPException(status_code=404, detail="Not found")
    items_html = "".join([f"<tr><td>{i['name']}</td><td>{i.get('description','')}</td><td>{i['quantity']}</td><td>{i['unit_price']}</td><td>{i.get('tax_rate',0)}%</td></tr>" for i in d.get("items", [])])
    html = f"""
    <html><head><title>Quote</title><style>body{{font-family:sans-serif;margin:2rem}}table{{width:100%;border-collapse:collapse}}td,th{{border:1px solid #eee;padding:8px}}</style></head>
    <body>
      <h1>Quote</h1>
      <p>Status: {d.get('status','Draft')}</p>
      <p>Company: {d.get('company_name','')}</p>
      <table><thead><tr><th>Item</th><th>Description</th><th>Qty</th><th>Unit Price</th><th>Tax</th></tr></thead>
      <tbody>{items_html}</tbody></table>
      <h2>Total: {d.get('total',0)}</h2>
    </body></html>
    """
    return HTMLResponse(content=html)


# ---------- Projects & Tasks ----------

@app.post("/projects")
def create_project(project: ProjectSchema, user: AuthUser = Depends(get_current_user)):
    data = project.model_dump()
    data.update({"owner_id": ObjectId(user._id), "created_at": datetime.now(timezone.utc)})
    _id = get_collection("project").insert_one(data).inserted_id
    return {"_id": str(_id), **project.model_dump()}


@app.get("/projects")
def list_projects(user: AuthUser = Depends(get_current_user)):
    docs = get_collection("project").find({"owner_id": ObjectId(user._id)}).sort("created_at", -1)
    return [{"_id": str(d.get("_id")), "name": d.get("name"), "description": d.get("description") } for d in docs]


@app.post("/tasks")
def create_task(task: TaskSchema, user: AuthUser = Depends(get_current_user)):
    data = task.model_dump()
    data["created_at"] = datetime.now(timezone.utc)
    _id = get_collection("task").insert_one(data).inserted_id
    return {"_id": str(_id), **task.model_dump()}


@app.get("/tasks")
def list_tasks(project_id: Optional[str] = None, status: Optional[str] = None, user: AuthUser = Depends(get_current_user)):
    query: Dict[str, Any] = {}
    if project_id:
        query["project_id"] = project_id
    if status:
        query["status"] = status
    docs = get_collection("task").find(query).sort("created_at", -1)
    res = []
    for d in docs:
        d["_id"] = str(d["_id"]) ; res.append(d)
    return res


@app.put("/tasks/{task_id}")
def update_task(task_id: str, task: TaskSchema, user: AuthUser = Depends(get_current_user)):
    res = get_collection("task").update_one({"_id": objid(task_id)}, {"$set": task.model_dump(), "$currentDate": {"updated_at": True}})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Task not found")
    return {"_id": task_id, **task.model_dump()}


@app.delete("/tasks/{task_id}")
def delete_task(task_id: str, user: AuthUser = Depends(get_current_user)):
    get_collection("task").delete_one({"_id": objid(task_id)})
    return {"ok": True}


# ---------- Settings & Users ----------

@app.get("/users")
def list_users(user: AuthUser = Depends(get_current_user)):
    if user.role != "Admin":
        raise HTTPException(status_code=403, detail="Admins only")
    docs = get_collection("user").find({})
    return [{"_id": str(d["_id"]), "name": d.get("name"), "email": d.get("email"), "role": d.get("role", "Employee")} for d in docs]


@app.post("/users")
def create_user(new_user: RegisterRequest, user: AuthUser = Depends(get_current_user)):
    if user.role != "Admin":
        raise HTTPException(status_code=403, detail="Admins only")
    users = get_collection("user")
    if users.find_one({"email": new_user.email}):
        raise HTTPException(status_code=400, detail="Email already exists")
    doc = {
        "name": new_user.name,
        "email": new_user.email,
        "role": new_user.role,
        "hashed_password": hash_password(new_user.password),
        "is_active": True,
        "created_at": datetime.now(timezone.utc),
    }
    _id = users.insert_one(doc).inserted_id
    return {"_id": str(_id), "name": doc["name"], "email": doc["email"], "role": doc["role"]}


@app.get("/settings")
def get_settings(user: AuthUser = Depends(get_current_user)):
    d = get_collection("settings").find_one({})
    if not d:
        d = {"company_name": None, "language": "en", "theme": "light"}
    else:
        d["_id"] = str(d["_id"]) if d.get("_id") else None
    return d


@app.put("/settings")
def update_settings(settings: SettingsSchema, user: AuthUser = Depends(get_current_user)):
    if user.role != "Admin":
        raise HTTPException(status_code=403, detail="Admins only")
    d = settings.model_dump()
    get_collection("settings").update_one({}, {"$set": d}, upsert=True)
    return d


# ---------- Dashboard ----------

@app.get("/dashboard/summary")
def dashboard_summary(user: AuthUser = Depends(get_current_user)):
    recent_contacts = list(get_collection("contact").find({}).sort("created_at", -1).limit(5))
    recent_quotes = list(get_collection("quote").find({"created_by": ObjectId(user._id)}).sort("created_at", -1).limit(5))
    recent_tasks = list(get_collection("task").find({}).sort("created_at", -1).limit(5))

    for arr in (recent_contacts, recent_quotes, recent_tasks):
        for d in arr:
            d["_id"] = str(d["_id"]) if d.get("_id") else None

    counts = {
        "clients": get_collection("contact").count_documents({"status": "Client"}),
        "quotes": get_collection("quote").count_documents({"created_by": ObjectId(user._id)}),
        "tasks_pending": get_collection("task").count_documents({"status": {"$in": ["To Do", "In Progress"]}}),
    }

    return {
        "recent_contacts": recent_contacts,
        "recent_quotes": recent_quotes,
        "recent_tasks": recent_tasks,
        "counts": counts,
    }


@app.get("/")
def root():
    return {"message": "SMB Operations API running"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
            response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️ Connected but Error: {str(e)[:50]}"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"
    return response


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
