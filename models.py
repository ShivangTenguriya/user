from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(db.Model, UserMixin):
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    mobile_number = db.Column(db.String(20), unique=True, nullable=False)
    latitude = db.Column(db.Float, nullable=True)
    longitude = db.Column(db.Float, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    appointments = db.relationship('Appointment', back_populates='user')

    


class ServiceProvider(db.Model,  UserMixin):
    __tablename__ = 'service_provider'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)  # Provider email
    password_hash = db.Column(db.String(256), nullable=False)
    name = db.Column(db.String(120))
    phone_number = db.Column(db.String(20))
    aadhar = db.Column(db.String(12))
    address = db.Column(db.String(250))
    experience_years = db.Column(db.Integer)
    skills = db.Column(db.Text)  # comma separated or JSON string

    userphoto = db.Column(db.String(250))  # file path or URL to uploaded photo
    documents = db.Column(db.Text)  # JSON string list of PDF filenames/paths
    document_type = db.Column(db.String(20), default='pdf')

    approved = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    appointments = db.relationship('Appointment', back_populates='provider')
    works = db.relationship('ProviderProfileWork', back_populates='provider')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Admin(db.Model):
    __tablename__ = 'admin'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class GadgetType(db.Model):
    __tablename__ = 'gadget_type'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)


class Appointment(db.Model):
    __tablename__ = 'appointment'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    provider_id = db.Column(db.Integer, db.ForeignKey('service_provider.id'), nullable=False)
    gadget_type_id = db.Column(db.Integer, db.ForeignKey('gadget_type.id'), nullable=False)

    model = db.Column(db.String(100))
    purchase_date = db.Column(db.Date)
    problem_description = db.Column(db.Text)
    preferred_time = db.Column(db.DateTime)
    status = db.Column(db.String(20), default='New')  # New, Pending, Completed, Cancelled, Rescheduled
    cancel_reason = db.Column(db.Text, nullable=True)
    reschedule_reason = db.Column(db.Text, nullable = False)
    reschedule_time = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = db.relationship('User', back_populates='appointments')
    provider = db.relationship('ServiceProvider', back_populates='appointments')
    gadget_type = db.relationship('GadgetType')
    rating = db.Column(db.Integer, nullable=True)
    comment = db.Column(db.Text, nullable=True)

    amount = db.Column(db.Integer, nullable = False)
    order_id = db.Column(db.String(100), nullable=False)
    payment_id = db.Column(db.String(100), nullable=False)
    payment_status = db.Column(db.Boolean, default = False)


class ProviderProfileWork(db.Model):
    __tablename__ = 'provider_profile_work'

    id = db.Column(db.Integer, primary_key=True)
    provider_id = db.Column(db.Integer, db.ForeignKey('service_provider.id'), nullable=False)
    title = db.Column(db.String(150))
    description = db.Column(db.Text)
    image_path = db.Column(db.String(250))  # Path or URL of the work image

    provider = db.relationship('ServiceProvider', back_populates='works')


