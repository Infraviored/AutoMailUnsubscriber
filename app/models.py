from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy import String, Integer, Text, ForeignKey
import datetime

db = SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(120), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(128), nullable=True)
    accounts: Mapped[list["LinkedAccount"]] = relationship(back_populates="owner", cascade="all, delete-orphan")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class LinkedAccount(db.Model):
    __tablename__ = 'linked_account'
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('user.id'))
    email_address: Mapped[str] = mapped_column(String(120), nullable=False)
    provider: Mapped[str] = mapped_column(String(50), nullable=False)
    imap_server: Mapped[str] = mapped_column(String(120), nullable=True)
    credentials: Mapped[str] = mapped_column(Text, nullable=True) # For storing encrypted credentials/tokens
    scan_results: Mapped[str] = mapped_column(Text, nullable=True) # JSON blob for scan results
    unsubscribed_log: Mapped[str] = mapped_column(Text, nullable=True) # JSON blob for unsubscribed links
    scan_history: Mapped[str] = mapped_column(Text, nullable=True) # JSON blob for scan history
    
    owner: Mapped["User"] = relationship(back_populates="accounts") 