


# Bug Tracker Backend API

This is a RESTful backend API built with Flask and SQLAlchemy that allows users to register, log in, report bugs, update them, and delete them securely. Each user can only access their own bugs.

## Features

- User registration and login with secure password hashing
- Session-based authentication and authorization
- Create, read, update, and delete (CRUD) bug reports linked to users
- Protected routes with a custom login_required decorator
- JSON API responses with proper HTTP status codes

## Technologies Used

- Python 3.x
- Flask
- Flask SQLAlchemy
- Werkzeug (for password hashing)
- SQLite (for the database)

## Getting Started

### Prerequisites

- Python 3.x installed
- `pip` package manager

### Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/yourusername/bug-tracker-backend.git
   cd bug-tracker-backend
   ```

2. Create and activate a virtual environment (optional but recommended):

  python3 -m venv venv
   source venv/bin/activate 
   On Windows: venv\Scripts\activate
   
3.	Install dependencies:

pip install -r requirements.txt


4.	Run the application:

python bug.py


5.	The API will be available at http://127.0.0.1:5000/

API Endpoints

Endpoint	Method	Description
/signup	POST	Register a new user
/login	POST	Log in and create a session
/logout	POST	Log out and clear the session
/bugs	POST	Create a new bug report
/bugs	GET	Get all bugs reported by logged-in user
/bugs/<bug_id>	PATCH	Update a bug by ID (own bugs only)
/bugs/<bug_id>	DELETE	Delete a bug by ID (own bugs only)

Usage
	•	Use tools like Postman or curl to interact with the API.
	•	Authenticate by logging in to receive a session cookie.
	•	Use the session cookie to access protected bug routes.

License

This project is open source and available under the MIT License.

