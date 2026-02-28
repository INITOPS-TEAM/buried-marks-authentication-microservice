# Authentication Service

A two-step authentication API service built with Django REST Framework  
This service provides secure user authentication using a combination of permanent credentials and daily secret codes issuing custom JWTs for frontend authorization  

## Features

* Step 1 validates permanent credentials and returns a secure, time-bound TimestampSigner token
* Step 2 validates a daily secret code and the temporary token to issue the  JWT access and refresh tokens
* JWT encryption utilizes the secure ES256 algorithm with Public/Private key pairs for token signing

## Enviroment Variables (.env)

Create a '.env' file in the root directory based on '.env.example'

## Local Setup and Running

* Start PostgreSQL container 'docker compose up -d'
* Create a virtual environment and activate it: 'python3 -m venv venv && source venv/bin/activate'
* Install all necessary dependencies: 'pip install -r requirements.txt'
* Apply migrations to create tables in the database: 'python manage.py migrate'
* Start the local server: 'python manage.py runserver'
