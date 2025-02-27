# GraphAuth – Graphical Pattern Authentication System with Multi-Factor Security

![GraphAuth Logo](./static/images/banner.png)  
*Optional: Replace with your project banner or logo*


## Overview

GraphAuth is a modern authentication system designed to replace traditional text-based passwords with a secure, graphical pattern-based method. Users create a unique password by selecting a sequence of images from a randomized grid. This innovative approach is further strengthened with OTP-based multi-factor authentication (MFA) and robust brute-force protection. The system is built with a scalable Go backend, MongoDB for data storage, and a responsive web UI using HTML, CSS, and JavaScript.


## Key Features

- **Graphical Pattern Authentication**  
  Users register and log in by selecting a sequence of images (from a pool of 38) arranged in a randomized grid. The selected sequence forms their unique password.

- **Randomized Image Grid**  
  Each time the grid is loaded, the image order is shuffled using the Fisher-Yates algorithm. This reduces the risk of shoulder surfing.

- **OTP-Based Multi-Factor Authentication (MFA)**  
  Upon successful pattern verification during login, a one-time passcode (OTP) is sent to the user’s registered email. This OTP (valid for 5 minutes) must be entered to complete the login process.

- **Brute-Force Protection**  
  The system tracks failed login attempts. After five consecutive failures, the account is temporarily locked for 1 minute. A real-time countdown is displayed on the UI, and an alert email is sent to notify the user.

- **Password Reset**  
  Users who forget their graphical pattern can request a password reset. A secure reset token is emailed to them, allowing them to set a new graphical password.

- **Responsive & Modern UI**  
  A clean, user-friendly web interface is provided for all interactions, including registration, login, OTP verification, and password reset. Real-time feedback and dynamic elements enhance the overall user experience.


## Workflow

1. **Registration:**
   - The user enters their username and email.
   - A randomized grid of 38 images is displayed.
   - The user selects images in their chosen order to create a pattern.
   - The selected sequence is combined into a string (e.g., `5-12-27-3`), hashed (using Bycrypt), and stored in the database along with an OTP secret.
   
2. **Login:**
   - The user enters their username and email on the login page.
   - They replicate their previously selected image sequence from a newly randomized grid.
   - The backend verifies the hashed pattern. If correct, an OTP is generated and sent to the user’s email.
   - If the pattern is wrong, the failed attempt counter is incremented; after five failures, the account is locked for 1 minute and an alert email is sent.

3. **OTP Verification:**
   - The user receives an OTP (valid for 5 minutes) via email.
   - The user enters the OTP on the OTP page.
   - Upon successful validation, the user is redirected to the dashboard.

4. **Forgot Password:**
   - The user provides their username and email.
   - A secure reset token is generated and sent to their email.
   - The user clicks the reset link and sets a new graphical pattern.

5. **Dashboard:**
   - After successful login, the dashboard displays detailed project information, showcasing key features, security measures, and design decisions.


## Technologies Used

- **Backend:**  
  - **Go (Golang)** with Gorilla Mux for RESTful API routing  
  - **MongoDB** for data storage  
  - **SMTP** for sending OTP and alert emails  
  - **pquerna/otp** for TOTP-based OTP generation

- **Frontend:**  
  - **HTML**, **CSS**, and **Vanilla JavaScript**  
  - Responsive layout using CSS Grid and Flexbox  
  - Custom styling with CSS variables


## Installation & Setup

1. **Clone the Repository:**  
   ```bash
   git clone https://github.com/yourusername/your-private-repo.git
   cd graphauth
   ```
2. **Install Dependencies:**
      Make sure you have Go (v1.18 or later) installed, then run:
  
   ```bash
   go mod tidy
   ```
3. **Configure Environment Variables:**
      Create a `.env` file in the project root with:

    ```dotenv

      # MongoDB Configuration
      MONGO_URI=mongodb://localhost:27017
      MONGO_DB=graphauth

      # SMTP Configuration for sending emails
      SMTP_SERVER=smtp.gmail.com:587
      SMTP_USER=your_email@gmail.com
      SMTP_PASSWORD=your_app_password
    ```
   Replace your_app_password with your SMTP provider’s app password.

4. **Run the Application:**

    ```bash
      go run main.go
    ```
    Your application will run on http://localhost:8080.

5. **Access the Application:**

    Navigate to http://localhost:8080 to view the home page.
    Register a new account, log in using your graphical pattern, and complete OTP verification.

## Usage

- **Registration:**  
  Enter your username and email, select your graphical pattern by clicking on images from the grid, and submit the form. Your selected sequence is securely hashed and stored.

- **Login:**  
  Reproduce your graphical pattern on a randomized grid. If the pattern is correct, an OTP is sent to your registered email. The UI displays real-time feedback, including a countdown if your account is locked due to too many failed attempts.

- **OTP Verification:**  
  Enter the OTP on the OTP verification page to complete your login and access the dashboard.

- **Forgot Password:**  
  Request a password reset by entering your username and email. Follow the reset link sent to your email to set a new graphical pattern.

## Future Enhancements

- **UI/UX Improvements:**  
  Consider integrating modern frontend frameworks (e.g., React with Material UI or Shadcn UI) for an even more polished interface.

- **Additional MFA Options:**  
  Explore SMS-based OTP, biometric authentication, or other multi-factor methods.

- **Advanced Session Management:**  
  Implement JWT-based session management and enhanced logging/monitoring for improved security and user management.

- **Scalability & Cloud Deployment:**  
  Containerize the application using Docker and deploy it to a cloud platform for greater scalability and production readiness.


