from datetime import datetime
from app import db

class User(db.Model):
    user_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.Enum('admin', 'normal'), nullable=False)
    occupation = db.Column(db.String(255))
    qualifications = db.Column(db.Text)
    bio = db.Column(db.Text)
    location = db.Column(db.String(255))
    profile_picture_url = db.Column(db.String(255))
    joined_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

class Cohort(db.Model):
    cohort_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    cohort_name = db.Column(db.String(255), nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

class CohortMember(db.Model):
    member_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    cohort_id = db.Column(db.Integer, db.ForeignKey('cohort.cohort_id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    joined_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

class Post(db.Model):
    post_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    cohort_id = db.Column(db.Integer, db.ForeignKey('cohort.cohort_id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

class Notification(db.Model):
    notification_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, nullable=False, default=False)

class Fundraiser(db.Model):
    fundraiser_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    cohort_id = db.Column(db.Integer, db.ForeignKey('cohort.cohort_id'), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    goal_amount = db.Column(db.Numeric(10, 2), nullable=False)
    current_amount = db.Column(db.Numeric(10, 2), nullable=False, default=0)
    created_by = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

class Advert(db.Model):
    advert_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    image_url = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

class AdminNotification(db.Model):
    admin_notification_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

class ChatMessage(db.Model):
    message_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

class ResetToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    token = db.Column(db.String(100), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
