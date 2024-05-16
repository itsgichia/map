from flask import Blueprint, jsonify, request
from models import User, Cohort, CohortMember, Post, Notification, Fundraiser, Advert, AdminNotification, ChatMessage, ResetToken
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from models import db  

# Create a Blueprint object
bp = Blueprint('routes', __name__)

# Example route: get all users
@bp.route('/users', methods=['GET'])
def get_users():
    users = User.query.all()
    user_data = [{'user_id': user.user_id, 'username': user.username} for user in users]
    return jsonify(user_data)

# Example route: create a new user
@bp.route('/users', methods=['POST'])
def create_user():
    data = request.json
    new_user = User(
        username=data['username'],
        email=data['email'],
        password_hash=data['password_hash'],
        role=data['role'],
        joined_at=datetime.utcnow()
    )
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User created successfully'}), 201

# Routes for managing cohorts
@bp.route('/cohorts', methods=['GET'])
def get_cohorts():
    cohorts = Cohort.query.all()
    cohort_data = [{'cohort_id': cohort.cohort_id, 'cohort_name': cohort.cohort_name} for cohort in cohorts]
    return jsonify(cohort_data)

# Example route: create a new cohort
@bp.route('/cohorts', methods=['POST'])
def create_cohort():
    data = request.json
    new_cohort = Cohort(
        cohort_name=data['cohort_name'],
        created_by=data['created_by'],
        created_at=datetime.utcnow()
    )
    db.session.add(new_cohort)
    db.session.commit()
    return jsonify({'message': 'Cohort created successfully'}), 201

# Routes for managing posts
@bp.route('/posts', methods=['GET'])
def get_posts():
    posts = Post.query.all()
    post_data = [{'post_id': post.post_id, 'content': post.content} for post in posts]
    return jsonify(post_data)

# Example route: create a new post
@bp.route('/posts', methods=['POST'])
def create_post():
    data = request.json
    new_post = Post(
        user_id=data['user_id'],
        cohort_id=data['cohort_id'],
        content=data['content'],
        created_at=datetime.utcnow()
    )
    db.session.add(new_post)
    db.session.commit()
    return jsonify({'message': 'Post created successfully'}), 201




# Route: Get all cohorts
@bp.route('/cohorts', methods=['GET'])
def get_cohorts():
    cohorts = Cohort.query.all()
    cohort_data = [{'cohort_id': cohort.cohort_id, 'cohort_name': cohort.cohort_name} for cohort in cohorts]
    return jsonify(cohort_data)

# Route: Create a new cohort
@bp.route('/cohorts', methods=['POST'])
def create_cohort():
    data = request.json
    cohort = Cohort(cohort_name=data['cohort_name'], created_by=data['created_by'], created_at=datetime.utcnow())
    db.session.add(cohort)
    db.session.commit()
    return jsonify({'message': 'Cohort created successfully'}), 201

# Route: Get all posts
@bp.route('/posts', methods=['GET'])
def get_posts():
    posts = Post.query.all()
    post_data = [{'post_id': post.post_id, 'user_id': post.user_id, 'content': post.content} for post in posts]
    return jsonify(post_data)

# Route: Create a new post
@bp.route('/posts', methods=['POST'])
def create_post():
    data = request.json
    post = Post(user_id=data['user_id'], cohort_id=data['cohort_id'], content=data['content'], created_at=datetime.utcnow())
    db.session.add(post)
    db.session.commit()
    return jsonify({'message': 'Post created successfully'}), 201

# Route: Get all notifications for a user
@bp.route('/notifications/<int:user_id>', methods=['GET'])
def get_notifications(user_id):
    notifications = Notification.query.filter_by(user_id=user_id).all()
    notification_data = [{'notification_id': notification.notification_id, 'content': notification.content} for notification in notifications]
    return jsonify(notification_data)

# Route: Create a new notification
@bp.route('/notifications', methods=['POST'])
def create_notification():
    data = request.json
    notification = Notification(user_id=data['user_id'], content=data['content'], created_at=datetime.utcnow())
    db.session.add(notification)
    db.session.commit()
    return jsonify({'message': 'Notification created successfully'}), 201

# Add more routes for other functionalities such as managing notifications, fundraisers, adverts, etc.

