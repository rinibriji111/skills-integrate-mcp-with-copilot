# Mergington High School Activities API

A super simple FastAPI application that allows students to view and sign up for extracurricular activities.

## Features

- View all available extracurricular activities
- Teacher sign-in to register and unregister students
- Public read-only activity and participant listings
- Persistent teacher credentials stored locally as password hashes

## Getting Started

1. Install the dependencies:

   ```
   pip install fastapi uvicorn
   ```

2. Run the application:

   ```
   python app.py
   ```

3. Open your browser and go to:
   - API documentation: http://localhost:8000/docs
   - Alternative documentation: http://localhost:8000/redoc

## API Endpoints

| Method | Endpoint                                                          | Description                                                         |
| ------ | ----------------------------------------------------------------- | ------------------------------------------------------------------- |
| GET    | `/activities`                                                     | Get all activities with their details and current participant count |
| POST   | `/auth/login`                                                      | Sign in as a teacher                                                |
| GET    | `/auth/me`                                                         | Get the signed-in teacher                                           |
| POST   | `/auth/logout`                                                     | Sign out                                                            |
| POST   | `/activities/{activity_name}/signup?email=student@mergington.edu` | Teacher: sign up a student                                          |
| DELETE | `/activities/{activity_name}/unregister?email=student@mergington.edu` | Teacher: unregister a student                                    |

## Teacher Accounts

Create or replace a teacher account with `python src/create_teacher.py`. The script prompts for a username and password, then stores a PBKDF2 password hash in `src/teachers.json`. That local file is ignored by Git; do not commit real credentials. Set `TEACHERS_FILE` to use a different credential file.

Students can view the activity list and participant emails without signing in. A teacher session expires after eight hours.

## Data Model

The application uses a simple data model with meaningful identifiers:

1. **Activities** - Uses activity name as identifier:

   - Description
   - Schedule
   - Maximum number of participants allowed
   - List of student emails who are signed up

2. **Students** - Uses email as identifier:
   - Name
   - Grade level

All data is stored in memory, which means data will be reset when the server restarts.
