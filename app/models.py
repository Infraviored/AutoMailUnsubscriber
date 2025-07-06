from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy import String, Integer, Text, ForeignKey, UniqueConstraint
import datetime

db = SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(120), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(128), nullable=True)
    accounts: Mapped[list["LinkedAccount"]] = relationship(back_populates="owner", cascade="all, delete-orphan")
    unsubscribe_links: Mapped[list["UnsubscribeLink"]] = relationship(back_populates="user", cascade="all, delete-orphan")

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
    
    owner: Mapped["User"] = relationship(back_populates="accounts")

class UnsubscribeLink(db.Model):
    __tablename__ = 'unsubscribe_link'
    __table_args__ = (UniqueConstraint('user_id', 'unsubscribe_url', name='_user_url_uc'),)

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('user.id'), nullable=False)
    list_name: Mapped[str] = mapped_column(String(255), nullable=False)
    unsubscribe_url: Mapped[str] = mapped_column(Text, nullable=False)
    added_at: Mapped[datetime.datetime] = mapped_column(default=datetime.datetime.utcnow, nullable=False)
    unsubscribed: Mapped[bool] = mapped_column(default=False, nullable=False)

    user: Mapped["User"] = relationship(back_populates="unsubscribe_links") 