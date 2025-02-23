GraphAuth – A Graphical Pattern Authentication System with Multi-Factor Security

Optional banner image for visual appeal

Overview
GraphAuth is a modern authentication system that replaces traditional text-based passwords with a graphical pattern-based approach. Users create their unique password by selecting a sequence from a grid of images. The system enhances security further by integrating OTP-based multi-factor authentication (MFA) and robust brute-force protection, which includes temporary account lockout and alert notifications. The project is built with a scalable Go backend, MongoDB for data storage, and a responsive web UI using HTML, CSS, and JavaScript.

Features
Graphical Pattern Authentication:
Users register and log in by selecting a sequence from a randomized grid of 38 images. The pattern (e.g., "5-12-27-3") is captured only in memory and transmitted securely.

Randomized Image Grid:
Each time the page loads, the image grid is shuffled using a Fisher-Yates algorithm, reducing the risk of shoulder surfing.

OTP-Based Multi-Factor Authentication (MFA):
After the pattern is verified at login, a one-time passcode (OTP) is generated (with a 5-minute validity) and sent to the user's registered email.

Brute-Force Protection:
The system tracks failed login attempts. After five consecutive failures, the account is temporarily locked for 1 minute, and an alert email is sent to the user. The login button is disabled during this period with a real-time countdown.

Forgot Password Functionality:
Users who forget their graphical pattern can request a password reset by providing their username and email. A secure, time-limited reset token is sent to their email, allowing them to set a new pattern.

Responsive & Modern UI:
A clean, modern web interface ensures a pleasant user experience on desktops and mobile devices.

How It Works
Registration Flow
User Input:
The user navigates to the registration page, enters their username and email, and is presented with a randomized grid of 38 images.
Pattern Selection:
The user clicks on images in a desired sequence to form their graphical password. Their selections are stored only in a temporary JavaScript array.
Submission & Storage:
Upon submission, the selected image IDs are joined (e.g., "5-12-27-3") and sent via HTTPS to the backend.
The backend hashes this sequence using SHA-256, generates an OTP secret for future MFA, and stores the user details in MongoDB.
Login Flow
User Input:
The user goes to the login page, enters their username and email, and re-creates their graphical pattern from a randomized grid.
Verification:
The backend verifies the provided pattern by hashing it and comparing it to the stored hash.
If correct, an OTP is generated and sent to the user’s email.
Brute-Force Protection:
Incorrect patterns increment a failure counter. After five failed attempts, the account is locked for 1 minute, with a real-time countdown disabling the login button.
An alert email is sent to notify the user of the suspicious activity.
OTP Verification:
The user enters the received OTP on the OTP page.
The backend validates the OTP, and upon success, the user is logged in and redirected to the dashboard.
Forgot Password Flow
Request:
On the login page, the user can click “Forgot Password?” and then enter their username and email.
Reset Process:
The backend generates a secure reset token with a 1-hour expiry and sends a reset link to the user’s email.
The user clicks the link and is prompted to create a new graphical pattern, which updates their stored password.
Dashboard & Feedback
Dashboard:
Once logged in, the user is redirected to a dashboard that displays detailed project information, including features and security measures.
Real-Time Feedback:
Users receive immediate feedback for actions (successful registration, login errors, OTP verification, lockout countdown, etc.), enhancing the overall user experience.
Technical Details
Backend:

Written in Go (Golang) using Gorilla Mux for RESTful routing.
MongoDB is used for data storage, with user details including username, email, hashed pattern, OTP secret, failed attempts, and lockout timestamps.
OTPs are generated using TOTP with a 5-minute validity period.
Brute-force protection includes tracking of failed login attempts, temporary account lockout, and alert email notifications.
SMTP settings are loaded from environment variables using godotenv.
Frontend:

Built with HTML, CSS, and vanilla JavaScript.
A dynamic, randomized image grid is generated on the registration and login pages for pattern selection.
Real-time UI elements, including a lockout countdown and error/success messages, enhance user interaction.
Installation & Setup
Clone the Repository:

bash
Copy
Edit
git clone <repository-url>
cd graphauth
Install Dependencies: Ensure you have Go (version 1.18+) installed, then run:

bash
Copy
Edit
go mod tidy
Configure Environment Variables: Create a .env file in the project root with:

dotenv
Copy
Edit
# MongoDB Configuration
MONGO_URI=mongodb://localhost:27017
MONGO_DB=graphauth

# SMTP Configuration for sending emails
SMTP_SERVER=smtp.gmail.com:587
SMTP_USER=your_email@gmail.com
SMTP_PASSWORD=your_app_password
Replace your_app_password with your SMTP provider’s app password.

Run the Application:

bash
Copy
Edit
go run main.go
The application will run on http://localhost:8080.

Access the Application:

Open your browser and navigate to http://localhost:8080 to view the home page.
Use the registration page to sign up and the login page to authenticate and receive an OTP.
Usage
Register:
Enter your details and select a graphical pattern from the randomized grid.
Your pattern is securely hashed and stored.
Login:
Reproduce your pattern on the login page. If the pattern is correct, you’ll receive an OTP via email.
OTP Verification:
Enter the OTP on the provided page to complete your login.
Forgot Password:
If needed, request a password reset by providing your username and email to receive a reset link.
Future Enhancements
Enhanced UI/UX:
Future iterations might use React with Material UI or Shadcn UI for a richer user experience.
Additional MFA Options:
Expanding MFA options, such as SMS-based OTPs or biometric integration.
Advanced Session Management:
Implementing JWT-based session management and improved monitoring for login attempts.
