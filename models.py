import datetime
from flask_login import UserMixin
from sqlalchemy import event, DDL

from app import db


class UserAccount(db.Model, UserMixin):
    __tablename__ = "user_account"
    id = db.Column('id', db.Integer, primary_key=True)
    screen_user_name = db.Column('screen_user_name', db.Unicode)
    user_details_id = db.Column('user_details_id', db.Integer, db.ForeignKey('user_details.id'), nullable=True)

    user_details = db.relationship('UserDetails', foreign_keys=user_details_id)


class UserDetails(db.Model):
    __tablename__ = "user_details"
    id = db.Column('id', db.Integer, primary_key=True)
    first_name = db.Column('first_name', db.Unicode)
    last_name = db.Column('last_name', db.Unicode)
    email = db.Column('email', db.Unicode)
    password_salt = db.Column('password_salt', db.Unicode)
    password_hash = db.Column('password_hash', db.Unicode)


class ExternalAuthenticationProvider(db.Model):
    __tablename__ = "external_authentication_provider"
    id = db.Column('id', db.Integer, primary_key=True)
    name = db.Column('name', db.Unicode)


class AsyncOperation(db.Model):
    __tablename__ = "async_operation"
    id = db.Column('id', db.Integer, primary_key=True)
    external_authentication_provider_id = db.Column('external_authentication_provider_id', db.Integer,
                                                  db.ForeignKey('external_authentication_provider.id'))
    async_operation_status_type_id = db.Column('async_operation_status_type_id', db.Integer,
                                               db.ForeignKey('async_operation_status_type.id'))
    user_external_login_id = db.Column('user_external_login_id', db.Integer, db.ForeignKey('user_external_login.id'))

    external_authentication_provider = db.relationship('ExternalAuthenticationProvider',
                                                       foreign_keys=external_authentication_provider_id)
    async_operation_status_type = db.relationship('AsyncOperationStatusType',
                                                  foreign_keys=async_operation_status_type_id)
    user_external_login = db.relationship('UserExternalLogin', foreign_keys=user_external_login_id)


class AsyncOperationStatusType(db.Model):
    __tablename__ = "async_operation_status_type"
    id = db.Column('id', db.Integer, primary_key=True)
    name = db.Column('name', db.Integer)


class UserExternalLogin(db.Model):
    __tablename__ = "user_external_login"
    id = db.Column('id', db.Integer, primary_key=True)
    external_authentication_provider_id = db.Column('external_authentication_provider_id', db.Integer,
                                                    db.ForeignKey('external_authentication_provider.id'))

    user_account_id = db.Column('user_account_id', db.Integer, db.ForeignKey('user_account.id'))
    external_authentication_provider = db.relationship('ExternalAuthenticationProvider',
                                                       foreign_keys=external_authentication_provider_id)
    external_user_id = db.Column('external_user_id', db.Integer)
    first_name = db.Column('first_name', db.Unicode)
    last_name = db.Column('last_name', db.Unicode)
    email = db.Column('email', db.Unicode)
    name = db.Column('name', db.Unicode)
    login_name = db.Column('login_name', db.Unicode)

    user_account = db.relationship('UserAccount', foreign_keys=user_account_id)


class TodoItem(db.Model):
    __tablename__="todo_item"
    id = db.Column('id', db.Integer, primary_key=True)
    user_account_id = db.Column('user_account_id', db.Integer, db.ForeignKey('user_account.id'))
    name = db.Column('name', db.Unicode)
    is_done = db.Column('is_done', db.Boolean, default=False)
    creation_date = db.Column('creation_date', db.Date, default=datetime.datetime.utcnow())
    deadline_date = db.Column('deadline_date', db.Date)

    user_account = db.relationship('UserAccount', foreign_keys=user_account_id)


# insert default types of statuses into async_operation_status_type table
event.listen(
        AsyncOperationStatusType.__table__, 'after_create',
        DDL(
                """ INSERT INTO async_operation_status_type (id,name) VALUES(1,'pending'),(2, 'ok'),(3, 'error'); """)
)

# insert default types of providers into external_authentication_provider table
event.listen(
        ExternalAuthenticationProvider.__table__, 'after_create',
        DDL(
                """ INSERT INTO external_authentication_provider (id,name) VALUES(1,'facebook'),(2, 'google'),(3, 'github'), (4, 'linkedin'); """)
)



