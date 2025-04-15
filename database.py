import sqlite3
import logging
import bcrypt
from contextlib import contextmanager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

DATABASE_NAME = "payroll_system.db"

def hash_password(password):
    # Generate a salt and hash the password
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode(), salt)
    return hashed_password

@contextmanager
def get_db_connection():
    """Context manager for database connections"""
    conn = None
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        conn.row_factory = sqlite3.Row  # Enable row factory for better row access
        yield conn
    except sqlite3.Error as e:
        logger.error(f"Database connection error: {e}")
        raise
    finally:
        if conn:
            conn.close()

def initialize_database():
    """Initialize the database with required tables."""
    try:
        with sqlite3.connect("payroll_system.db") as conn:
            cursor = conn.cursor()

            # Create TblEmployees if it doesn't exist
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS TblEmployees (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    employee_no TEXT UNIQUE NOT NULL,
                    firstname TEXT NOT NULL,
                    lastname TEXT NOT NULL,
                    sex TEXT NOT NULL,
                    age INTEGER NOT NULL,
                    address TEXT NOT NULL,
                    contact TEXT NOT NULL,
                    rate_per_hour DECIMAL(10,2) NOT NULL,
                    department TEXT NOT NULL,
                    position TEXT NOT NULL,
                    employment_status TEXT NOT NULL,
                    date_hired DATE NOT NULL,
                    email TEXT,
                    emergency_contact TEXT,
                    emergency_contact_relationship TEXT,
                    sss_no TEXT,
                    philhealth_no TEXT,
                    pagibig_no TEXT,
                    tin_no TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Create trigger to update the updated_at timestamp
            cursor.execute("""
                CREATE TRIGGER IF NOT EXISTS update_employee_timestamp 
                AFTER UPDATE ON TblEmployees
                BEGIN
                    UPDATE TblEmployees 
                    SET updated_at = CURRENT_TIMESTAMP 
                    WHERE id = NEW.id;
                END;
            """)

            # Create TblPassword if it doesn't exist
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS TblPassword (
                    employee_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    username TEXT UNIQUE NOT NULL,
                    password BLOB NOT NULL,
                    email TEXT,
                    role TEXT NOT NULL DEFAULT 'user',
                    status TEXT NOT NULL DEFAULT 'active'
                )
            """)

            # Create login_audit table if it doesn't exist
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS login_audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    success INTEGER NOT NULL,
                    ip_address TEXT,
                    FOREIGN KEY (username) REFERENCES TblPassword(username)
                )
            """)

            # Create TblPayroll if it doesn't exist
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS TblPayroll (
                    payroll_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    employee_no TEXT NOT NULL,
                    firstname TEXT NOT NULL,
                    lastname TEXT NOT NULL,
                    rate DECIMAL(10,2) NOT NULL,
                    number_hours_work DECIMAL(10,2) NOT NULL,
                    late_deduction DECIMAL(10,2) DEFAULT 0,
                    undertime_hours DECIMAL(10,2) DEFAULT 0,
                    undertime_deduction DECIMAL(10,2) DEFAULT 0,
                    cash_advance DECIMAL(10,2) DEFAULT 0,
                    gross_pay DECIMAL(10,2) NOT NULL,
                    sss DECIMAL(10,2) DEFAULT 0,
                    philhealth DECIMAL(10,2) DEFAULT 0,
                    pagibig DECIMAL(10,2) DEFAULT 0,
                    total_deduc DECIMAL(10,2) DEFAULT 0,
                    netpay DECIMAL(10,2) NOT NULL,
                    date TEXT NOT NULL,
                    FOREIGN KEY (employee_no) REFERENCES TblEmployees(employee_no)
                )
            """)

            conn.commit()
            logging.info("Database schema updated successfully")

    except sqlite3.Error as e:
        logging.error(f"Database initialization error: {e}")
        raise

def insert_test_data():
    """Insert test data into the database"""
    try:
        conn = sqlite3.connect("payroll_system.db")
        cursor = conn.cursor()

        # Insert admin user for login
        cursor.execute("""
            INSERT OR REPLACE INTO TblUser (username, password, role)
            VALUES (?, ?, ?)
        """, ('admin', 'admin123', 'admin'))

        conn.commit()
        conn.close()
        logger.info("Test data inserted successfully")
        
    except sqlite3.Error as e:
        logger.error(f"Error inserting test data: {e}")
        if conn:
            conn.close()

def get_employee(employee_no):
    """Get employee details by employee number"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM TblEmployees WHERE employee_no = ?", (employee_no,))
            return cursor.fetchone()
    except sqlite3.Error as e:
        logger.error(f"Error fetching employee {employee_no}: {e}")
        raise

def get_payroll_history(employee_no, start_date=None, end_date=None):
    """Get payroll history for an employee with optional date range"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            query = "SELECT * FROM TblPayroll WHERE employee_no = ?"
            params = [employee_no]
            
            if start_date and end_date:
                query += " AND date BETWEEN ? AND ?"
                params.extend([start_date, end_date])
            
            cursor.execute(query, params)
            return cursor.fetchall()
    except sqlite3.Error as e:
        logger.error(f"Error fetching payroll history for employee {employee_no}: {e}")
        raise

def create_initial_admin():
    """Create the initial admin account if it doesn't exist."""
    try:
        with sqlite3.connect("payroll_system.db") as conn:
            cursor = conn.cursor()
            
            # Check if admin account exists
            cursor.execute("SELECT * FROM TblPassword WHERE role='admin'")
            if cursor.fetchone() is None:
                # Create admin account with default credentials
                admin_password = hash_password("admin123")  # Default password
                cursor.execute("""
                    INSERT INTO TblPassword (name, username, password, email, role, status)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, ("Administrator", "admin", admin_password, "admin@example.com", "admin", "active"))
                
                conn.commit()
                print("Initial admin account created successfully!")
                print("Default admin credentials:")
                print("Username: admin")
                print("Password: admin123")
                print("Please change these credentials after first login.")
            else:
                print("Admin account already exists.")

    except sqlite3.Error as e:
        print(f"Database error: {e}")
        raise

def get_user_role(username):
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT role FROM TblPassword WHERE username = ?", (username,))
            result = cursor.fetchone()
            if result:
                return result['role']
            else:
                logger.error("User not found")
                return 'user'
    except sqlite3.Error as e:
        logger.error(f"Error getting user role: {e}")
        return 'user'

if __name__ == "__main__":
    initialize_database()
    create_initial_admin()