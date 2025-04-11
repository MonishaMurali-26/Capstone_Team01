# Vehicle Data Management & Reporting System

A system designed for Northwest Missouri State University to manage vehicle data, track fuel usage and maintenance records, and generate regulatory reports.

## Project Information

- **Team Name:** Team Rolex
- **Section:** 44693-02
- **Team Number:** 01

## Features

- **Vehicle Management:** Add, edit, and deactivate vehicle records
- **Fuel Usage Tracking:** Log fuel consumption, costs, and mileage
- **Maintenance Records:** Document service history and costs
- **Reporting:** Generate monthly and annual reports for compliance
- **Analytics:** Visualize fuel usage and maintenance costs
- **User Management:** Role-based access control (Admin/User)
- **Alerts:** Automated notifications for irregular data patterns

## Technology Stack

- **Framework:** Flask (Python)
- **Database:** SQLite
- **ORM:** SQLAlchemy
- **Visualization:** Matplotlib
- **Data Processing:** Pandas
- **Frontend:** Bootstrap 5, Font Awesome

## Setup Instructions

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

### Installation

1. Clone the repository:
   ```
   git clone <repository-url>
   cd vehicle-management-system
   ```

2. Create a virtual environment:
   ```
   python -m venv venv
   ```

3. Activate the virtual environment:
   - Windows: `venv\Scripts\activate`
   - macOS/Linux: `source venv/bin/activate`

4. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

5. Set up the database:
   ```
   python app.py
   ```
   This will automatically create the database and a default admin user.

### Running the Application

1. Start the Flask server:
   ```
   python app.py
   ```

2. Access the application in your browser at:
   ```
   http://localhost:5000
   ```

3. Login with the default admin credentials:
   - Username: `admin`
   - Password: `admin123`
   
   (Be sure to change these credentials after first login)

## Project Structure

- `app.py` - Main application file with routes and database models
- `templates/` - HTML templates for the web interface
- `static/` - CSS, JavaScript, and other static files
- `static/reports/` - Generated Excel reports (created during runtime)

## Default User Credentials

- **Admin User:**
  - Username: admin
  - Password: admin123

## Team Members

- **Rajesh Singamsetty (Project Manager):** Overall coordination, timeline management, and report delivery
- **Prasanna Kumar Dokala (Developer):** Design and development of system features
- **Monisha Murali (Tester):** Testing and validation of data and system functionality
- **Tarun Srinivas Kothapalli (Data Analyst):** Design of reporting tools and database optimization
- **Sai Charan Reddy Konda (UI/UX Designer):** Development of user-friendly interface aesthetics