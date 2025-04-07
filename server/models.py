from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin
from config import db, bcrypt

class User(db.Model, SerializerMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)  # Added unique and nullable constraints
    _password_hash = db.Column(db.String, nullable=False)  # Added nullable constraint

    # Add serialization rules to exclude password hash
    serialize_rules = ('-password_hash', '-_password_hash',)

    @hybrid_property
    def password_hash(self):
        raise AttributeError('Password hashes may not be viewed.')

    @password_hash.setter
    def password_hash(self, password):
        if len(password) < 6:
            raise ValueError("Password must be at least 6 characters long")
        password_hash = bcrypt.generate_password_hash(
            password.encode('utf-8'))
        self._password_hash = password_hash.decode('utf-8')

    def authenticate(self, password):
        return bcrypt.check_password_hash(
            self._password_hash, password.encode('utf-8'))

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username
        }

    def __repr__(self):
        return f'User {self.username}, ID: {self.id}'