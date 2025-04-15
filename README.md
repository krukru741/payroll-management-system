# Payroll Management System

A comprehensive desktop application for managing employee information, payroll processing, and HR administration built with Python and Tkinter.

## Features

- **User Authentication System**
  - Secure login with role-based access control (Admin, Manager, User)
  - Password encryption using bcrypt
  - Password recovery functionality
  - Account management with status tracking

- **Employee Management**
  - Complete employee profile management
  - Personal and employment information
  - Government ID management (SSS, PhilHealth, Pag-IBIG, TIN)
  - Emergency contact information
  - Department and position tracking

- **Payroll Processing**
  - Automated salary calculation
  - Support for overtime and undertime
  - Deduction management
  - Government contribution calculations
    - SSS
    - PhilHealth
    - Pag-IBIG
  - Payslip generation and printing
  - Export functionality to Excel

- **System Features**
  - Modern and intuitive UI
  - Search and filter capabilities
  - Data export to Excel
  - Printable reports
  - Secure database storage

## Technical Requirements

- Python 3.x
- Required Python packages:
  - tkinter
  - tkcalendar
  - sqlite3
  - pandas
  - reportlab
  - bcrypt
  - logging

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/payroll-management-system.git
```

2. Install required packages:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
python main.py
```

## Initial Setup

- The system will automatically create a database on first run
- Default admin account will be created:
  - Username: admin
  - Password: admin123
  - (Please change these credentials after first login)

## Database Structure

The system uses SQLite3 with the following main tables:
- TblPassword: User authentication and roles
- TblEmployees: Employee information
- TblPayroll: Payroll records
- login_audit: Login attempt tracking

## Security Features

- Password hashing using bcrypt
- Role-based access control
- Login attempt tracking
- Session management
- Account status monitoring

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Built with Python and Tkinter
- Uses SQLite for database management
- Modern UI design with custom styling 