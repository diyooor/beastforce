---

# Webapp

A simple web application built on top of boost beast. 

## Roadmap (what do I want to do for the next 9999 years)
- [x] user roles (admin/non-admin)
    - [x] need to add role to the json response of validate session
- [x] admin dashboard () (maybe the easiest with user roles -- to do today)
    - [x] need to add additional div elements to the client and separate them by the role retrieved from the session

- support tickets
    - [x] created message struct 
    - [] vector of messages in userservice
    - [] admins can view messages by sender
    - [] admins can respond 
    - [] normal users can add messages once the ticket is open
    - [] admins can see when normal users have seen the response
    - need to add a tab for support tickets in both admin and non-admin dashboard 
- support chat
    - pop up chat box would be cool here
- catalog (items in a shop)
    - need to separate the login and actual home landing page which would be a catalog of items to buy in this case
- calendar scheduling (date time appointments with availablity)
    - add a normal user tab and admin tab for calendar availability and scheduling
    - also need a object for calendar
- payment processing (stripe for calendar scheduling and catalog)
    - use the ClientService within the create-stripe-checkout endpoint
- other user account management things (delete account, password recovery once email functionality is set up)
- calendar scheduling (schedule date/time appointments with payment)

## Features

- User login and registration
- Password change
- Server status dashboard (CPU usage, requests, etc.)
- Timed session management
- Allocate/deallocate system memory
## Files

- `index.html`: Frontend HTML and CSS
- `main.cpp`: Backend server logic

## Getting Started

1. Clone the repository.
2. Compile `main.cpp`:
   ```sh
   g++ -o main main.cpp -lpthread -std=c++17
   ```
3. Run the server:
   ```sh
   ./main 0.0.0.0 8080 . 1
   ```
4. Open `localhost:8080/` in your browser.

## API Endpoints

- `/login`: User login
- `/register`: User registration
- `/logout`: User logout
- `/status`: Get server status
- `/password`: Change password
- `/external`: Execute external requests
- `/validate-session`: Validate sessions

## Dependencies

- g++
- Boost 1.85.0
- Web browser

## Usage

- Navigate to the login page.
- Register a new account or log in with existing credentials.
- Access the dashboard to view server status or change your password.

---

## Screenshots
Ticket demo
- [[images/1.png]]
- check images
