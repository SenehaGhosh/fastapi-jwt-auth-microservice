# FastAPI JWT Authentication Service

A secure, modular RESTful API microservice built with FastAPI, SQLAlchemy (SQLite), and JWT authentication.

## Features
- User registration with password hashing (`passlib` & `bcrypt`)
- OAuth2 Password Flow login returning JWT access tokens (`python-jose`)
- Protected endpoints validated via OAuth2 Bearer tokens
- Automated SQLite database table creation on app startup
- Interactive API documentation powered by Swagger UI

## Setup & Running
1. Clone the repository
2. Install dependencies:
   ```bash
   pip install fastapi uvicorn "python-jose[cryptography]" "passlib[bcrypt]" sqlalchemy