#!/usr/bin/env python
from flask import request, session
from flask_restful import Resource

from config import app, db, api
from models import User

class ClearSession(Resource):
    def delete(self):
        session['page_views'] = None
        session['user_id'] = None
        return {}, 204

class Signup(Resource):
    def post(self):
        json = request.get_json()
        user = User(
            username=json['username']
        )
        user.password_hash = json['password']
        db.session.add(user)
        db.session.commit()
        
        # Store the user's ID in the session to log them in
        session['user_id'] = user.id
        return user.to_dict(), 201

class CheckSession(Resource):
    def get(self):
        # Check if user is logged in by looking for user_id in session
        user_id = session.get('user_id')
        if user_id:
            user = User.query.filter(User.id == user_id).first()
            return user.to_dict(), 200
        # Return empty response with 204 status if not logged in
        return {}, 204

class Login(Resource):
    def post(self):
        json = request.get_json()
        username = json['username']
        password = json['password']
        
        # Find the user by username
        user = User.query.filter(User.username == username).first()
        
        # Verify password and authenticate user
        if user and user.authenticate(password):
            # Store user's ID in session to log them in
            session['user_id'] = user.id
            return user.to_dict(), 200
        # Return error if authentication fails
        return {'error': 'Invalid username or password'}, 401

class Logout(Resource):
    def delete(self):
        # Remove user_id from session to log out
        if 'user_id' in session:
            session.pop('user_id')
        return {}, 204

# Add all resources to the API
api.add_resource(ClearSession, '/clear', endpoint='clear')
api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')

if __name__ == '__main__':
    app.run(port=5555, debug=True)