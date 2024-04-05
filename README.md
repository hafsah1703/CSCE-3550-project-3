# Project3: User Authentication and Logging

## Description

Project3 is a Flask-based web application that provides user authentication functionality and logging of authentication requests. It allows users to register, authenticate, and logs the authentication requests along with the request IP address and timestamp.

## Features

- **User Registration**: Users can register by providing a username and email address. A secure password is generated for each user upon registration.
- **User Authentication**: Registered users can authenticate using their username and password.
- **Logging**: Authentication requests are logged along with the request IP address and timestamp.
- **Database Storage**: User information and authentication logs are stored in an SQLite database.

## Installation

1. Clone the repository to your local machine:

    ```
    git clone <repository-url>
    ```

2. Navigate to the project directory:

    ```
    cd Project3
    ```

3. Install dependencies:

    ```
    pip install -r requirements.txt
    ```

4. Run the application:

    ```
    python app3.py
    ```
## Usage

1. **Registration**:
    - Endpoint: `/register`
    - Method: `POST`
    - Request Body: JSON object with `username` and `email`
    - Response: JSON object with `password` (generated for the user)

    Example:
    ```
    curl -X POST -H "Content-Type: application/json" -d '{"username": "example_user", "email": "user@example.com"}' http://localhost:8080/register
    ```

2. **Authentication**:
    - Endpoint: `/auth`
    - Method: `POST`
    - Request Body: JSON object with `username` and `password`
    - Response: `Authentication successful` or `Authentication failed`

    Example:
    ```
    curl -X POST -H "Content-Type: application/json" -d '{"username": "example_user", "password": "your_password"}' http://localhost:8080/auth
    ```

## Database

- The application uses an SQLite database named `your_database.db` to store user information and authentication logs.
- The database schema includes tables for `users` and `auth_logs`.

## Configuration

- You can modify the port number and other configurations in the `app3.py` file as needed.


## License

This project is licensed under the [MIT License](LICENSE).

## Contact

If you have any questions or need further assistance, please don't hesitate to contact me at [hafsahiqbal@my.unt.edu](hafsahiqbal@my.unt.edu).

