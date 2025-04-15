import contextlib
import os
import pandas as pd
from tkinter import filedialog
from tkinter import *
import tkinter.ttk as ttk
import tkinter as tk
import tkinter.messagebox as tkMessageBox
from tkinter import messagebox
from tkinter import filedialog
from tkcalendar import DateEntry
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from queue import Queue, Empty
from sqlite3 import connect
from contextlib import contextmanager
import sqlite3
import logging
from database import initialize_database, create_initial_admin
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_LEFT, TA_CENTER
from datetime import datetime
import subprocess
import threading
from flask import request
import bcrypt  # Add this line

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# At the top of your file, add:
class UserSession:
    """Store current user session information."""
    def __init__(self):
        self.username = None
        self.role = None
        
    def set_user(self, username, role):
        self.username = username
        self.role = role
        self.username = username
        self.role = role

    def clear(self):
        self.username = None
        self.role = None

current_session = UserSession()

def hash_password(password):
    """
    Hash the provided password using bcrypt.
    """
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode(), salt)
    return hashed_password

def check_login(username, password):
    """
    Check if the provided username and password are valid.
    """
    try:
        with sqlite3.connect("payroll_system.db") as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT password, role, status 
                FROM TblPassword 
                WHERE username=?
            """, (username,))
            record = cursor.fetchone()
            
            if not record:
                return False
                
            stored_password, role, status = record
            
            if status != 'active':
                tkMessageBox.showwarning(
                    'Account Inactive', 
                    'This account is not active. Please contact an administrator.', 
                    icon="warning"
                )
                return False
                
            if bcrypt.checkpw(password.encode(), stored_password):
                # Store the user's role in the check_password function
                check_login.user_role = role
                return True
            return False
            
    except sqlite3.Error as e:
        logger.error(f"Login error: {e}")
        return False

def login():
    """
    Display the login window and handle user authentication.
    """
    failure_max = 3

    def validate_password_strength(password):
        """Validate the strength of a password."""
        if len(password) < 8:
            return False, "Password must be at least 8 characters"
        if not any(c.isupper() for c in password):
            return False, "Password must contain uppercase letter"
        if not any(c.islower() for c in password):
            return False, "Password must contain lowercase letter"
        if not any(c.isdigit() for c in password):
            return False, "Password must contain a number"
        return True, ""

    def logout():
        """Log out the user and return to the login window."""
        global main_window
        session_timer.cancel()
        login()
        if 'main_window' in globals():
            main_window.destroy()

    def start_session_timer():
        """Start a timer that logs out the user after a specified duration."""
        global session_timer
        session_timer = threading.Timer(3600, logout)  # 1 hour timeout
        session_timer.start()

    def log_login_attempt(username, success, ip_address):
        """Log login attempts to the database."""
        try:
            conn = sqlite3.connect("payroll_system.db")
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO login_audit (username, success, ip_address)
                VALUES (?, ?, ?)
            """, (username, 1 if success else 0, ip_address))
            
            conn.commit()
        except sqlite3.Error as e:
            print(f"Error logging login attempt: {e}")
        finally:
            cursor.close()
            conn.close()

    def enter(event):
        """Handle the Enter key press event."""
        check_password()

    def check_password():
        """Check the validity of the entered username and password."""
        global current_session  # Add this line to access the global session
        
        username = login_user.get()
        password = login_password.get()
        
        if not username or not password:
            tkMessageBox.showwarning('', 'Please enter both username and password', icon="warning")
            return
        
        result = check_login(username, password)
        if result:
            try:
                # Get the user's role from the database
                with sqlite3.connect("payroll_system.db") as conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT role FROM TblPassword WHERE username=?", (username,))
                    role = cursor.fetchone()[0]
                    
                    # Set the session
                    current_session.set_user(username, role)
                    print(f"Session set - Username: {current_session.username}, Role: {current_session.role}")  # Debug line
                    
            except sqlite3.Error as e:
                logger.error(f"Database error while setting session: {e}")
                return
                
            check_password.user = username
            log_login_attempt(username, True, '127.0.0.1')
            print('in')
            start_session_timer()
            login.destroy()
            main_menu()
        else:
            log_login_attempt(username, False, '127.0.0.1')
            check_password.failures += 1
            if check_password.failures == failure_max:
                login.destroy()
                raise SystemExit(tkMessageBox.showwarning(
                    '', 'Unauthorized login attempt', icon="warning"))
            else:
                login.title('Try again. Attempt')
                tkMessageBox.showwarning(
                    '', 'Invalid username or password', icon="warning")
                login_user.delete(0, END)
                login_password.delete(0, END)

    check_password.failures = 0

    def open_create_account_window():
        """Handle the create account functionality."""
        # Get current user's role and ensure we're using the actual role value
        current_user_role = get_user_role(current_session.username)
        
        create_account_window = Toplevel()
        create_account_window.title("Create Account")
        create_account_window.geometry("600x750")
        create_account_window.config(bg="#E3F2FD")

        # Define available options based on user role
        roles = ["user", "admin", "manager"] if current_user_role.lower() == "admin" else ["user"]
        statuses = ["active", "inactive", "suspended"] if current_user_role.lower() == "admin" else ["active"]

        # Debug print to check role values
        print(f"Current user role: {current_user_role}")
        print(f"Available roles: {roles}")

        # Department-specific positions dictionary
        department_positions = {
            "Administration": [
                "Administrative Director",
                "Office Manager",
                "Executive Assistant",
                "Administrative Assistant",
                "Receptionist",
                "Office Coordinator",
                "Records Manager",
                "Facilities Manager"
            ],
            "Human Resources": [
                "HR Director",
                "HR Manager",
                "HR Specialist",
                "Recruitment Coordinator",
                "Training Coordinator",
                "Benefits Administrator",
                "HR Analyst",
                "Employee Relations Manager",
                "HR Assistant"
            ],
            "Finance": [
                "Finance Director",
                "Finance Manager",
                "Senior Accountant",
                "Financial Analyst",
                "Payroll Specialist",
                "Budget Analyst",
                "Tax Specialist",
                "Treasury Analyst",
                "Bookkeeper"
            ],
            "IT": [
                "IT Director",
                "IT Manager",
                "System Administrator",
                "Network Engineer",
                "Software Developer",
                "Database Administrator",
                "Security Specialist",
                "IT Support Specialist",
                "DevOps Engineer"
            ],
            "Building Maintenance": [
                "Maintenance Director",
                "Maintenance Manager",
                "Facilities Supervisor",
                "Building Engineer",
                "HVAC Technician",
                "Electrician",
                "Plumber",
                "General Maintenance Technician",
                "Maintenance Assistant",
                "Groundskeeper",
                "Carpenter",
                "Painter",
                "Utility Worker",
                "Janitor",
                "Custodian"
            ],
            "Facilities & Utilities": [
                "Facilities Director",
                "Utilities Manager",
                "Facilities Supervisor",
                "Utility Supervisor",
                "Senior Utility Worker",
                "Utility Technician",
                "Utility Worker",
                "Waste Management Specialist",
                "Energy Systems Operator",
                "Water Systems Technician",
                "Facilities Coordinator",
                "Utility Maintenance Worker",
                "Sanitation Worker",
                "Cleaning Supervisor",
                "Cleaning Staff"
            ]
        }

        # Get list of departments from department_positions dictionary
        departments = list(department_positions.keys())

        # Create a canvas with scrollbar
        canvas = Canvas(create_account_window, bg="#E3F2FD")
        scrollbar = ttk.Scrollbar(create_account_window, orient="vertical", command=canvas.yview)
        scrollable_frame = Frame(canvas, bg="#E3F2FD")

        # Configure the canvas
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        # Create a window in the canvas for the scrollable frame
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        # Pack the scrollbar and canvas
        scrollbar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        # Main frame (now inside scrollable_frame)
        main_frame = Frame(scrollable_frame, bg="#E3F2FD")
        main_frame.pack(expand=True, fill=BOTH, padx=30, pady=20)

        # Variables
        name_var = StringVar()
        username_var = StringVar()
        password_var = StringVar()
        confirm_password_var = StringVar()
        email_var = StringVar()
        contact_var = StringVar()
        department_var = StringVar()
        position_var = StringVar()
        role_var = StringVar(value=roles[0])  # Set default role
        status_var = StringVar(value=statuses[0])  # Set default status

        def update_positions(*args):
            """Update position options based on selected department"""
            selected_dept = department_var.get()
            if selected_dept in department_positions:
                position_combo['values'] = department_positions[selected_dept]
                position_var.set(department_positions[selected_dept][0])  # Set first position as default

        # Create sections with their fields
        sections = [
            {
                "title": "Account Information",
                "fields": [
                    ("Full Name*:", name_var),
                    ("Username*:", username_var),
                    ("Password*:", password_var, "password"),
                    ("Confirm Password*:", confirm_password_var, "password")
                ]
            },
            {
                "title": "Contact Details",
                "fields": [
                    ("Email:", email_var),
                    ("Contact:", contact_var)
                ]
            },
            {
                "title": "Employment Details",
                "fields": []  # We'll handle department and position separately
            },
            {
                "title": "System Access",
                "fields": []  # We'll handle role and status separately
            }
        ]

        # Create each section
        for section in sections:
            section_frame = LabelFrame(main_frame, 
                                     text=section["title"],
                                     font=('Helvetica', 12, 'bold'),
                                     bg="#E3F2FD",
                                     fg="#0D47A1",
                                     padx=15,
                                     pady=10)
            section_frame.pack(fill=X, pady=10)

            if section["title"] == "Employment Details":
                # Department field
                dept_frame = Frame(section_frame, bg="#E3F2FD")
                dept_frame.pack(fill=X, pady=5)
                Label(dept_frame, 
                      text="Department*:", 
                      bg="#E3F2FD",
                      font=('Helvetica', 10),
                      width=15, 
                      anchor=W).pack(side=LEFT, padx=5)
                dept_combo = ttk.Combobox(dept_frame, 
                                        textvariable=department_var,
                                        values=departments, 
                                        state='readonly',
                                        width=30)
                dept_combo.pack(side=LEFT, fill=X, expand=True)
                
                # Position field
                pos_frame = Frame(section_frame, bg="#E3F2FD")
                pos_frame.pack(fill=X, pady=5)
                Label(pos_frame, 
                      text="Position*:", 
                      bg="#E3F2FD",
                      font=('Helvetica', 10),
                      width=15, 
                      anchor=W).pack(side=LEFT, padx=5)
                position_combo = ttk.Combobox(pos_frame, 
                                            textvariable=position_var,
                                            state='readonly',
                                            width=30)
                position_combo.pack(side=LEFT, fill=X, expand=True)

                # Bind department selection to position update
                department_var.trace('w', update_positions)
                
                # Set initial department and update positions
                if not department_var.get() and departments:
                    department_var.set(departments[0])
                    update_positions()

            elif section["title"] == "System Access":
                # Role field
                role_frame = Frame(section_frame, bg="#E3F2FD")
                role_frame.pack(fill=X, pady=5)
                Label(role_frame, 
                      text="Role*:", 
                      bg="#E3F2FD",
                      font=('Helvetica', 10),
                      width=15, 
                      anchor=W).pack(side=LEFT, padx=5)
                role_combo = ttk.Combobox(role_frame, 
                                        textvariable=role_var,
                                        values=roles, 
                                        state='readonly',
                                        width=30)
                role_combo.pack(side=LEFT, fill=X, expand=True)
                role_combo.set(roles[0])  # Set default value
                
                # Status field
                status_frame = Frame(section_frame, bg="#E3F2FD")
                status_frame.pack(fill=X, pady=5)
                Label(status_frame, 
                      text="Status*:", 
                      bg="#E3F2FD",
                      font=('Helvetica', 10),
                      width=15, 
                      anchor=W).pack(side=LEFT, padx=5)
                status_combo = ttk.Combobox(status_frame, 
                                          textvariable=status_var,
                                          values=statuses, 
                                          state='readonly',
                                          width=30)
                status_combo.pack(side=LEFT, fill=X, expand=True)
                status_combo.set(statuses[0])  # Set default value

            else:
                # Handle other fields
                for field in section["fields"]:
                    field_frame = Frame(section_frame, bg="#E3F2FD")
                    field_frame.pack(fill=X, pady=5)
                    
                    Label(field_frame, 
                          text=field[0], 
                          bg="#E3F2FD",
                          font=('Helvetica', 10),
                          width=15, 
                          anchor=W).pack(side=LEFT, padx=5)
                    
                    if len(field) > 2 and field[2] == "password":
                        Entry(field_frame, 
                             textvariable=field[1],
                             show="*",
                             width=32).pack(side=LEFT, fill=X, expand=True)
                    else:
                        Entry(field_frame, 
                             textvariable=field[1],
                             width=32).pack(side=LEFT, fill=X, expand=True)

        def create_account():
            """Create a new employee account."""
            if not all([name_var.get(), username_var.get(), 
                       password_var.get(), confirm_password_var.get()]):
                messagebox.showwarning("", "Please fill all required fields!", icon="warning")
                return

            # Add password strength validation
            is_valid, message = validate_password_strength(password_var.get())
            if not is_valid:
                messagebox.showwarning("", message, icon="warning")
                return

            # Check password match
            if password_var.get() != confirm_password_var.get():
                messagebox.showwarning("", "Passwords do not match!", icon="warning")
                return

            try:
                conn = sqlite3.connect("payroll_system.db")
                cursor = conn.cursor()

                # Check if username exists
                cursor.execute("SELECT * FROM TblUser WHERE username=?", (username_var.get(),))
                if cursor.fetchone():
                    messagebox.showwarning("", "Username already exists!", icon="warning")
                    return

                # Hash the password
                hashed_password = hash_password(password_var.get())

                # Insert into TblUser
                user_data = (
                    username_var.get(),
                    hashed_password,
                    role_var.get(),
                    email_var.get(),
                    contact_var.get(),
                    department_var.get(),
                    position_var.get()
                )

                cursor.execute("""
                    INSERT INTO TblUser (username, password, role, email, contact, 
                                       department, position)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, user_data)

                # Insert into TblPassword
                password_data = (
                    name_var.get(),
                    username_var.get(),
                    hashed_password,
                    email_var.get(),
                    role_var.get(),
                    status_var.get()
                )

                cursor.execute("""
                    INSERT INTO TblPassword (name, username, password, email, role, status)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, password_data)

                conn.commit()
                
                # Log the account creation
                logger.info(f"New account created by {current_session.username}: {username_var.get()} with role {role_var.get()}")
                
                messagebox.showinfo("Success", "Account created successfully!")
                create_account_window.destroy()

            except sqlite3.Error as e:
                messagebox.showerror("Database Error", f"An error occurred: {str(e)}")
                conn.rollback()
            finally:
                cursor.close()
                conn.close()

        # Title Section
        title_frame = Frame(main_frame, bg="#E3F2FD")
        title_frame.pack(fill=X, pady=(0, 20))
        
        Label(title_frame, text="Create New Account", 
              font=('Helvetica', 20, 'bold'),
              bg="#E3F2FD", 
              fg="#0D47A1").pack()
        
        Label(title_frame, text="* Required fields", 
              font=('Helvetica', 10),
              fg="red",
              bg="#E3F2FD").pack()

        # Password requirements section
        req_frame = LabelFrame(main_frame, 
                              text="Password Requirements",
                              font=('Helvetica', 12, 'bold'),
                              bg="#E3F2FD",
                              fg="#0D47A1",
                              padx=15,
                              pady=10)
        req_frame.pack(fill=X, pady=10)
        
        Label(req_frame, 
              text="• Minimum 8 characters\n• At least one uppercase letter\n• At least one lowercase letter\n• At least one number",
              justify=LEFT,
              bg="#E3F2FD",
              font=('Helvetica', 10)).pack(anchor=W)

        # Buttons frame
        button_frame = Frame(main_frame, bg="#E3F2FD")
        button_frame.pack(pady=20)

        # Style buttons
        button_style = {
            'font': ('Helvetica', 11, 'bold'),
            'width': 15,
            'height': 2,
            'cursor': 'hand2'
        }

        Button(button_frame, 
               text="Create Account",
               command=create_account,
               bg="#1976D2",
               fg="white",
               **button_style).pack(side=LEFT, padx=10)
               
        Button(button_frame,
               text="Cancel",
               command=create_account_window.destroy,
               bg="#757575",
               fg="white",
               **button_style).pack(side=LEFT, padx=10)

        # Add mouse wheel scrolling
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")

        canvas.bind_all("<MouseWheel>", _on_mousewheel)

        # Bind arrow keys for scrolling
        def _on_up_key(event):
            canvas.yview_scroll(-1, "units")

        def _on_down_key(event):
            canvas.yview_scroll(1, "units")

        create_account_window.bind("<Up>", _on_up_key)
        create_account_window.bind("<Down>", _on_down_key)

        # Center window
        create_account_window.update_idletasks()
        width = 600  # Fixed width
        height = min(750, create_account_window.winfo_screenheight() - 100)  # Adjust height to screen
        x = (create_account_window.winfo_screenwidth() // 2) - (width // 2)
        y = (create_account_window.winfo_screenheight() // 2) - (height // 2)
        create_account_window.geometry(f"{width}x{height}+{x}+{y}")

        # Make sure the window doesn't get too small
        create_account_window.minsize(600, 500)

        # Bind department selection to position update
        department_var.trace('w', update_positions)
        
        # Initialize positions for first department
        update_positions()

    def forgot_password():
        """Handle the forgot password functionality."""
        forgot_window = Toplevel()
        forgot_window.title("Password Recovery")
        forgot_window.geometry("500x400")
        forgot_window.config(bg="#E3F2FD")

        # Variables
        username_var = StringVar()
        email_var = StringVar()
        new_password_var = StringVar()
        confirm_password_var = StringVar()

        def reset_password():
            """Handle password reset process."""
            username = username_var.get()
            email = email_var.get()
            new_password = new_password_var.get()
            confirm_password = confirm_password_var.get()

            # Validate inputs
            if not all([username, email, new_password, confirm_password]):
                messagebox.showwarning("", "Please fill all fields!", icon="warning")
                return

            # Validate password match
            if new_password != confirm_password:
                messagebox.showwarning("", "Passwords do not match!", icon="warning")
                return

            # Validate password strength
            is_valid, message = validate_password_strength(new_password)
            if not is_valid:
                messagebox.showwarning("", message, icon="warning")
                return

            try:
                # Verify user exists and email matches
                conn = sqlite3.connect("payroll_system.db")
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT email FROM TblUser 
                    WHERE username = ?
                """, (username,))
                result = cursor.fetchone()
                
                if not result:
                    messagebox.showwarning("", "Username not found!", icon="warning")
                    return
                    
                if result[0] != email:
                    messagebox.showwarning("", "Email does not match our records!", icon="warning")
                    return

                # Hash the new password
                hashed_password = hash_password(new_password)

                # Update password in both tables
                cursor.execute("""
                    UPDATE TblUser 
                    SET password = ? 
                    WHERE username = ?
                """, (hashed_password, username))

                cursor.execute("""
                    UPDATE TblPassword 
                    SET password = ? 
                    WHERE username = ?
                """, (hashed_password, username))

                conn.commit()
                messagebox.showinfo("Success", "Password has been reset successfully!")
                forgot_window.destroy()

            except sqlite3.Error as e:
                messagebox.showerror("Database Error", f"An error occurred: {str(e)}")
                conn.rollback()
            finally:
                cursor.close()
                conn.close()

        # Main frame
        main_frame = Frame(forgot_window, bg="#E3F2FD")
        main_frame.pack(expand=True, fill=BOTH, padx=20, pady=20)

        # Title
        Label(main_frame, text="Password Recovery", font=('Helvetica', 16, 'bold'),
            bg="#E3F2FD", fg="#0D47A1").pack(pady=10)

        # Form frame
        form_frame = Frame(main_frame, bg="#E3F2FD")
        form_frame.pack(fill=X, pady=10)

        # Username field
        username_frame = Frame(form_frame, bg="#E3F2FD")
        username_frame.pack(fill=X, pady=5)
        Label(username_frame, text="Username:", bg="#E3F2FD",
            width=15, anchor=W).pack(side=LEFT, padx=5)
        Entry(username_frame, textvariable=username_var).pack(side=LEFT, fill=X, expand=True)

        # Email field
        email_frame = Frame(form_frame, bg="#E3F2FD")
        email_frame.pack(fill=X, pady=5)
        Label(email_frame, text="Email:", bg="#E3F2FD",
            width=15, anchor=W).pack(side=LEFT, padx=5)
        Entry(email_frame, textvariable=email_var).pack(side=LEFT, fill=X, expand=True)

        # New Password field
        new_pass_frame = Frame(form_frame, bg="#E3F2FD")
        new_pass_frame.pack(fill=X, pady=5)
        Label(new_pass_frame, text="New Password:", bg="#E3F2FD",
            width=15, anchor=W).pack(side=LEFT, padx=5)
        Entry(new_pass_frame, textvariable=new_password_var,
            show="*").pack(side=LEFT, fill=X, expand=True)

        # Confirm Password field
        confirm_frame = Frame(form_frame, bg="#E3F2FD")
        confirm_frame.pack(fill=X, pady=5)
        Label(confirm_frame, text="Confirm Password:", bg="#E3F2FD",
            width=15, anchor=W).pack(side=LEFT, padx=5)
        Entry(confirm_frame, textvariable=confirm_password_var,
            show="*").pack(side=LEFT, fill=X, expand=True)

        # Password requirements label
        Label(form_frame, text="Password must contain:", bg="#E3F2FD",
            fg="#666666").pack(anchor=W, pady=5)
        Label(form_frame, text="• At least 8 characters\n• One uppercase letter\n• One lowercase letter\n• One number",
            bg="#E3F2FD", fg="#666666", justify=LEFT).pack(anchor=W, padx=20)

        # Buttons frame
        button_frame = Frame(main_frame, bg="#E3F2FD")
        button_frame.pack(pady=20)

        Button(button_frame, text="Reset Password", command=reset_password,
            bg="#1976D2", fg="white", width=15).pack(side=LEFT, padx=5)
        Button(button_frame, text="Cancel", command=forgot_window.destroy,
            bg="#1976D2", fg="white", width=15).pack(side=LEFT, padx=5)

        # Center the window
        forgot_window.update_idletasks()
        width = forgot_window.winfo_width()
        height = forgot_window.winfo_height()
        x = (forgot_window.winfo_screenwidth() // 2) - (width // 2)
        y = (forgot_window.winfo_screenheight() // 2) - (height // 2)
        forgot_window.geometry(f"{width}x{height}+{x}+{y}")

    # Create the login window
    login = Tk()
    login.title("Log in Window")
    width = 700
    height = 400
    screen_width = login.winfo_screenwidth()
    screen_height = login.winfo_screenheight()
    x = (screen_width / 2) - (width / 2)
    y = (screen_height / 2) - (height / 2)
    login.geometry("%dx%d+%d+%d" % (width, height, x, y))
    login.resizable(False, False)
    login.config(bg="#E3F2FD")

    # Create the login form
    frame = Frame(login, bg='#E3F2FD')
    frame.pack()

    parent = LabelFrame(frame, text="Login", relief=RIDGE, foreground='#0D47A1',
                       bg='#E3F2FD', font=('Courier', 18))
    parent.grid(row=0, column=0, sticky="news", padx=10, pady=20)

    Label(parent, text='Username:', font=('Courier', 15), fg='#0D47A1',
          bg='#E3F2FD').grid(row=3, column=0, padx=10, pady=10)
    login_user = Entry(parent, font=('Courier', 15), relief=RIDGE, bd=5)
    login_user.grid(row=3, column=1, padx=10, pady=10, sticky='w')

    Label(parent, text='Password:', font=('Courier', 15), fg='#0D47A1',
          bg='#E3F2FD').grid(row=4, column=0, padx=10, pady=10)
    login_password = Entry(parent, font=('Courier', 15),
                          relief=RIDGE, bd=5, show="*")
    login_password.grid(row=4, column=1, padx=10, pady=10, sticky='w')

    # Add buttons
    Button(frame, text="Login", foreground='#FFFFFF', bg='#1976D2', 
           font=('Courier', 15), relief=RIDGE, 
           command=check_password).grid(row=4, column=0, sticky="news", padx=10, pady=2)
    
    Button(frame, text="Forgot Password", foreground='#0D47A1', 
           bg='#BBDEFB', font=('Courier', 15), relief=RIDGE,
           command=forgot_password).grid(row=5, column=0, sticky="news", padx=10, pady=2)
    
    Button(frame, text="Create Account", foreground='#0D47A1', 
           bg='#BBDEFB', font=('Courier', 15), relief=RIDGE,
           command=open_create_account_window).grid(row=6, column=0, sticky="news", padx=10, pady=2)

    login_password.bind('<Return>', enter)
    
    login.mainloop()

def main_menu():
    """
    Display the main menu window.
    """
    main_window = Tk()
    main_window.title("Payroll Management System")
    main_window.configure(bg='#E3F2FD')  # Light Blue background
    width = 640
    height = 480
    screen_width = main_window.winfo_screenwidth()
    screen_height = main_window.winfo_screenheight()
    x = (screen_width / 2) - (width / 2)
    y = (screen_height / 2) - (height / 2)
    main_window.geometry("%dx%d+%d+%d" % (width, height, x, y))
    main_window.resizable(False, False)

    menubar = Menu(main_window)

    menu_file = Menu(menubar, bg='white', activebackground='aqua', tearoff=0)
    menubar.add_cascade(label="System Task", menu=menu_file)
    menu_file.add_command(
        label="Employee`s Registration Profile", command=menu_registration)
    menu_file.add_command(label="Employee`s List", command=menu_list)
    menu_file.add_separator()
    menu_file.add_command(label="Exit", command=main_window.destroy)

    menu_edit = Menu(menubar, bg='white', activebackground='aqua', tearoff=0)
    menubar.add_cascade(label="System Maintenance", menu=menu_edit)
    menu_edit.add_command(label="Password Management", command=menu_manage)
    menu_edit.add_command(label="Login Password", command=login)

    payroll_menu = Menu(menubar, bg='white', activebackground='aqua', tearoff=0)
    menubar.add_cascade(label="Payroll", menu=payroll_menu)
    payroll_menu.add_command(label="Payroll Calculator", command=lambda: menu_payroll())
    payroll_menu.add_command(label="Payroll List", command=payroll_list)

    main_window.config(menu=menubar)
    main_window.mainloop()

def menu_payroll():
    """
    Display the payroll calculator window.
    """
    # Variables
    EMPLOYEE_NO = StringVar()
    FIRSTNAME = StringVar()
    LASTNAME = StringVar()
    RATE = StringVar()
    NUMBER_HOURS_WORK = StringVar()
    CASH_ADVANCE = StringVar()
    SSS = StringVar()
    PHILHEALTH = StringVar()
    PAGIBIG = StringVar()
    GROSS_PAY = StringVar()
    TOTAL_DEDUC = StringVar()
    NETPAY = StringVar()
    DAYS_COVERED = StringVar()
    LATE_DEDUCTION = StringVar()
    OVERTIME_HOURS = StringVar()
    OVERTIME_PAY = StringVar()
    UNDERTIME_HOURS = StringVar()
    reg_search_var = StringVar()

    # Initialize variables with default values
    for var in [CASH_ADVANCE, LATE_DEDUCTION, OVERTIME_HOURS, UNDERTIME_HOURS]:
        var.set("0")

    def OnSelected(event):
        """
        Handle the selection of an employee in the treeview.
        """
        global employee_id
        curItem = tree.focus()
        contents = (tree.item(curItem))
        selectedItem = contents['values']
        if selectedItem:  # Check if an item was actually selected
            employee_id = selectedItem[0]
            EMPLOYEE_NO.set(selectedItem[1])
            FIRSTNAME.set(selectedItem[2])
            LASTNAME.set(selectedItem[3])
            RATE.set(selectedItem[8])  # Rate is in the 9th column
            
            # Clear other fields
            NUMBER_HOURS_WORK.set("")
            OVERTIME_HOURS.set("0")
            UNDERTIME_HOURS.set("0")
            LATE_DEDUCTION.set("0")
            CASH_ADVANCE.set("0")
            DAYS_COVERED.set("")
            SSS.set("")
            PHILHEALTH.set("")
            PAGIBIG.set("")
            GROSS_PAY.set("")
            TOTAL_DEDUC.set("")
            NETPAY.set("")
            OVERTIME_PAY.set("")

    def validate_required_fields():
        """
        Validate the required fields in the payroll calculator.
        """
        missing_fields = []
        fields_to_check = [
            (EMPLOYEE_NO.get(), "Employee No"),
            (NUMBER_HOURS_WORK.get(), "Number of Hours"),
            (DAYS_COVERED.get(), "Days Covered")
        ]

        for value, field_name in fields_to_check:
            if not value.strip():
                missing_fields.append(field_name)

        if missing_fields:
            message = "Please fill in the following required fields:\n• " + "\n• ".join(missing_fields)
            messagebox.showwarning('Required Fields', message, icon="warning")
            return False
        return True

    def calculate_deductions():
        """
        Calculate the deductions for the payroll entry.
        """
        if not validate_required_fields():
            return

        try:
            # Get values and convert to float, using 0 as default for optional fields
            rate = float(RATE.get())
            number_hours_work = float(NUMBER_HOURS_WORK.get())
            days_covered = float(DAYS_COVERED.get())
            cash_advance = float(CASH_ADVANCE.get() or "0")
            late_deduction = float(LATE_DEDUCTION.get() or "0")
            overtime_hours = float(OVERTIME_HOURS.get() or "0")
            undertime_hours = float(UNDERTIME_HOURS.get() or "0")

            # Calculate overtime rate (1.5x the regular rate)
            overtime_rate = rate * 1.5
            overtime_pay = overtime_hours * overtime_rate
            OVERTIME_PAY.set(f"{overtime_pay:.2f}")

            # Calculate total hours worked (adjust for undertime)
            total_hours_worked = (number_hours_work * days_covered) - undertime_hours

            # Calculate gross pay (regular pay + overtime pay)
            gross_pay = (total_hours_worked * rate) + overtime_pay
            GROSS_PAY.set(f"{gross_pay:.2f}")

            # Calculate deductions
            sss_contribution = calculate_SSS(gross_pay)
            philhealth_contribution = calculate_PHILHEALTH(gross_pay)
            pagibig_contribution = calculate_PAGIBIG(gross_pay)
            
            # Set deduction values
            SSS.set(f"{sss_contribution:.2f}")
            PHILHEALTH.set(f"{philhealth_contribution:.2f}")
            PAGIBIG.set(f"{pagibig_contribution:.2f}")

            # Calculate total deductions
            total_deductions = (sss_contribution + philhealth_contribution + 
                              pagibig_contribution + cash_advance + late_deduction)
            TOTAL_DEDUC.set(f"{total_deductions:.2f}")

            # Calculate net pay
            net_pay = gross_pay - total_deductions
            NETPAY.set(f"{net_pay:.2f}")

        except ValueError as e:
            messagebox.showwarning('', 'Please enter valid numeric values', icon="warning")
            logging.error(f"Error calculating deductions: {e}")

    def submit_payroll():
        """
        Submit the payroll entry and save it to the database.
        """
        if not validate_required_fields():
            return
            
        try:
            # Get all values needed for payroll entry
            employee_no = EMPLOYEE_NO.get()
            firstname = FIRSTNAME.get()
            lastname = LASTNAME.get()
            rate = float(RATE.get())
            number_hours_work = float(NUMBER_HOURS_WORK.get())
            overtime_hours = float(OVERTIME_HOURS.get() or "0")
            overtime_pay = float(OVERTIME_PAY.get() or "0")
            undertime_hours = float(UNDERTIME_HOURS.get() or "0")
            late_deduction = float(LATE_DEDUCTION.get() or "0")
            gross_pay = float(GROSS_PAY.get() or "0")
            cash_advance = float(CASH_ADVANCE.get() or "0")
            sss = float(SSS.get() or "0")
            philhealth = float(PHILHEALTH.get() or "0")
            pagibig = float(PAGIBIG.get() or "0")
            total_deduc = float(TOTAL_DEDUC.get() or "0")
            netpay = float(NETPAY.get() or "0")
            date = DAYS_COVERED.get()

            # Insert into database
            with sqlite3.connect("payroll_system.db") as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO TblPayroll (
                        employee_no, firstname, lastname, rate, 
                        number_hours_work, overtime_hours, overtime_pay,
                        undertime_hours, late_deduction,
                        gross_pay, cash_advance, sss, philhealth, 
                        pagibig, total_deduc, netpay, date
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    employee_no, firstname, lastname, rate,
                    number_hours_work, overtime_hours, overtime_pay,
                    undertime_hours, late_deduction,
                    gross_pay, cash_advance, sss, philhealth,
                    pagibig, total_deduc, netpay, date
                ))
                
            messagebox.showinfo("Success", "Payroll entry saved successfully!")
            clear_fields()
            reg_search_callback()  # Refresh the list

        except (ValueError, sqlite3.Error) as e:
            messagebox.showerror("Error", f"Failed to save payroll entry: {str(e)}")
            logging.error(f"Error saving payroll entry: {e}")

    def clear_fields():
        """
        Clear all fields in the payroll calculator.
        """
        for var in [EMPLOYEE_NO, FIRSTNAME, LASTNAME, RATE, NUMBER_HOURS_WORK,
                   OVERTIME_HOURS, UNDERTIME_HOURS, LATE_DEDUCTION, CASH_ADVANCE,
                   DAYS_COVERED, SSS, PHILHEALTH, PAGIBIG, GROSS_PAY,
                   TOTAL_DEDUC, NETPAY, OVERTIME_PAY]:
            var.set("")

    def calculate_SSS(gross_pay):
        """
        Calculate the SSS contribution for the given gross pay.
        """
        if gross_pay < 4250:
            return 180 + 10
        elif gross_pay >= 4250 and gross_pay < 4750:
            return 202.50 + 10
        elif gross_pay >= 4750 and gross_pay < 5250:
            return 225 + 10
        elif gross_pay >= 5250 and gross_pay < 5750:
            return 247.50 + 10
        elif gross_pay >= 5750 and gross_pay < 6250:
            return 270 + 10
        elif gross_pay >= 6250 and gross_pay < 6750:
            return 292.50 + 10
        elif gross_pay >= 6750 and gross_pay < 7250:
            return 315 + 10
        elif gross_pay >= 7250 and gross_pay < 7750:
            return 337.50 + 10
        elif gross_pay >= 7750 and gross_pay < 8250:
            return 360 + 10
        elif gross_pay >= 8250 and gross_pay < 8750:
            return 382.50 + 10
        elif gross_pay >= 8750 and gross_pay < 9250:
            return 405 + 10
        elif gross_pay >= 9250 and gross_pay < 9750:
            return 427.50 + 10
        elif gross_pay >= 9750 and gross_pay < 10250:
            return 450 + 10
        elif gross_pay >= 10250 and gross_pay < 10750:
            return 472.50 + 10
        elif gross_pay >= 10750 and gross_pay < 11250:
            return 495 + 10
        elif gross_pay >= 11250 and gross_pay < 11750:
            return 517.50 + 10
        elif gross_pay >= 11750 and gross_pay < 12250:
            return 540 + 10
        elif gross_pay >= 12250 and gross_pay < 12750:
            return 562.50 + 10
        elif gross_pay >= 12750 and gross_pay < 13250:
            return 585 + 10
        elif gross_pay >= 13250 and gross_pay < 13750:
            return 607.50 + 10
        elif gross_pay >= 13750 and gross_pay < 14250:
            return 630 + 10
        elif gross_pay >= 14250 and gross_pay < 14750:
            return 652.50 + 10
        elif gross_pay >= 14750 and gross_pay < 15250:
            return 675 + 30
        elif gross_pay >= 15250 and gross_pay < 15750:
            return 697.50 + 30
        elif gross_pay >= 15750 and gross_pay < 16250:
            return 720 + 30
        elif gross_pay >= 16250 and gross_pay < 16750:
            return 742.50 + 30
        elif gross_pay >= 16750 and gross_pay < 17250:
            return 765 + 30
        elif gross_pay >= 17250 and gross_pay < 17750:
            return 787.50 + 30
        elif gross_pay >= 17750 and gross_pay < 18250:
            return 810 + 30
        elif gross_pay >= 18250 and gross_pay < 18750:
            return 832.50 + 30
        elif gross_pay >= 18750 and gross_pay < 19250:
            return 855 + 30
        elif gross_pay >= 19250 and gross_pay < 19750:
            return 877.50 + 30
        elif gross_pay >= 19750 and gross_pay < 20250:
            return 900 + 30
        elif gross_pay >= 20250 and gross_pay < 20750:
            return 900 + 30 + 22.50
        elif gross_pay >= 20750 and gross_pay < 21250:
            return 900 + 30 + 45
        elif gross_pay >= 21250 and gross_pay < 21750:
            return 900 + 30 + 67.50
        elif gross_pay >= 21750 and gross_pay < 22250:
            return 900 + 30 + 90
        elif gross_pay >= 22250 and gross_pay < 22750:
            return 900 + 30 + 112.50
        elif gross_pay >= 22750 and gross_pay < 23250:
            return 900 + 30 + 135
        elif gross_pay >= 23250 and gross_pay < 23750:
            return 900 + 30 + 157.50
        elif gross_pay >= 23750 and gross_pay < 24250:
            return 900 + 30 + 180
        elif gross_pay >= 24250 and gross_pay < 24750:
            return 900 + 30 + 202.50
        elif gross_pay >= 24750 and gross_pay < 25250:
            return 900 + 30 + 225
        elif gross_pay >= 25250 and gross_pay < 25750:
            return 900 + 30 + 247.50
        elif gross_pay >= 25750 and gross_pay < 26250:
            return 900 + 30 + 270
        elif gross_pay >= 26250 and gross_pay < 26750:
            return 900 + 30 + 292.50
        elif gross_pay >= 26750 and gross_pay < 27250:
            return 900 + 30 + 315
        elif gross_pay >= 27250 and gross_pay < 27750:
            return 900 + 30 + 337.50
        elif gross_pay >= 27750 and gross_pay < 28250:
            return 900 + 30 + 360
        elif gross_pay >= 28250 and gross_pay < 28750:
            return 900 + 30 + 382.50
        elif gross_pay >= 28750 and gross_pay < 29250:
            return 900 + 30 + 405
        elif gross_pay >= 29250 and gross_pay < 29750:
            return 900 + 30 + 427.50
        elif gross_pay >= 29750:
            return 900 + 30 + 450

    def calculate_PAGIBIG(gross_pay):
        """
        Calculate the PAGIBIG contribution for the given gross pay.
        """
        if gross_pay >= 1000 and gross_pay < 1500:
            return gross_pay * 0.01
        elif gross_pay >= 1500 and gross_pay < 5000:
            return gross_pay * 0.02
        elif gross_pay >= 5000:
            return gross_pay * 0.03

    def calculate_PHILHEALTH(gross_pay):
        """
        Calculate the PHILHEALTH contribution for the given gross pay.
        """
        if gross_pay < 1000:
            return 0
        elif gross_pay >= 1000 and gross_pay <= 90000:
            total_contribution = gross_pay * 0.05  # Updated to 5%
        else:
            total_contribution = 90000 * 0.05  # Cap at maximum contribution

        employee_share = total_contribution / 2
        employer_share = total_contribution / 2
        return employee_share  # Return only the employee's share

    def reg_search_callback(*args):
        """
        Search for employees based on the provided search term.
        """
        search_term = reg_search_var.get()
        conn = sqlite3.connect("payroll_system.db")
        cursor = conn.cursor()
        tree.delete(*tree.get_children())
        cursor.execute(
            "SELECT * FROM 'TblEmployees' WHERE lastname LIKE ? ORDER BY employee_no",
            (f'%{search_term}%',))
        for row in cursor.fetchall():
            tree.insert("", "end", values=row)

    reg_window = Toplevel()
    reg_window.title("Employee`s Payroll")
    reg_window.configure(bg='#E3F2FD')  # Light Blue background
    width = 1300
    height = 600
    screen_width = reg_window.winfo_screenwidth()
    screen_height = reg_window.winfo_screenheight()
    x = (screen_width / 2) - (width / 2)
    y = (screen_height / 2) - (height / 2)
    reg_window.geometry("%dx%d+%d+%d" % (width, height, x, y))
    reg_window.resizable(False, False)

    signup_frame = Frame(reg_window, bg='#E3F2FD')  # Light Blue background
    signup_frame.pack()

    # Employee's Payroll Form
    user_info_frame = LabelFrame(signup_frame, text="Employee's Payroll", foreground='#0D47A1', bg='#E3F2FD',
                                font=('Courier', 18))  # Dark Blue text
    user_info_frame.grid(row=0, column=0, sticky="news", padx=30, pady=15)

    # Employee Information
    Label(user_info_frame, text="Employee No :", foreground='#0D47A1', bg='#E3F2FD', font=('Courier', 13)).grid(row=0, column=0, sticky="w")
    Entry(user_info_frame, textvariable=EMPLOYEE_NO, relief=RIDGE, bd=5).grid(row=0, column=1, columnspan=3, sticky="we", padx=10, pady=10)

    Label(user_info_frame, text="First Name :", foreground='#0D47A1', bg='#E3F2FD', font=('Courier', 13)).grid(row=1, column=0, sticky="w")
    Entry(user_info_frame, textvariable=FIRSTNAME).grid(row=1, column=1, padx=10, pady=10)

    Label(user_info_frame, text="Last Name :", foreground='#0D47A1', bg='#E3F2FD', font=('Courier', 13)).grid(row=1, column=2, sticky="w")
    Entry(user_info_frame, textvariable=LASTNAME).grid(row=1, column=3, padx=10, pady=10)

    # Rate and Hours Worked
    Label(user_info_frame, text="Rate :", foreground='#0D47A1', bg='#E3F2FD', font=('Courier', 13)).grid(row=2, column=0, sticky="w")
    Entry(user_info_frame, textvariable=RATE).grid(row=2, column=1, padx=10, pady=10)

    Label(user_info_frame, text="Number hours :", foreground='#0D47A1', bg='#E3F2FD', font=('Courier', 13)).grid(row=2, column=2, sticky="w")
    Entry(user_info_frame, textvariable=NUMBER_HOURS_WORK).grid(row=2, column=3, padx=10, pady=10)

    # Cash Advance and Days Covered
    Label(user_info_frame, text="Cash Advance :", foreground='#0D47A1', bg='#E3F2FD', font=('Courier', 13)).grid(row=3, column=0, sticky="w")
    Entry(user_info_frame, textvariable=CASH_ADVANCE).grid(row=3, column=1, padx=10, pady=10)

    Label(user_info_frame, text="Days Covered:", foreground='#0D47A1', bg='#E3F2FD', font=('Courier', 13)).grid(row=3, column=2, sticky="w")
    Entry(user_info_frame, textvariable=DAYS_COVERED).grid(row=3, column=3, padx=10, pady=10)

    # Late Deduction, Overtime, and Undertime
    Label(user_info_frame, text="Late Deduction:", foreground='#0D47A1', bg='#E3F2FD', font=('Courier', 13)).grid(row=4, column=0, sticky="w")
    Entry(user_info_frame, textvariable=LATE_DEDUCTION).grid(row=4, column=1, padx=10, pady=10)

    Label(user_info_frame, text="Overtime Hours:", foreground='#0D47A1', bg='#E3F2FD', font=('Courier', 13)).grid(row=5, column=0, sticky="w")
    Entry(user_info_frame, textvariable=OVERTIME_HOURS).grid(row=5, column=1, padx=10, pady=10)

    Label(user_info_frame, text="Overtime Pay:", foreground='#0D47A1', bg='#E3F2FD', font=('Courier', 13)).grid(row=5, column=2, sticky="w")
    Entry(user_info_frame, textvariable=OVERTIME_PAY).grid(row=5, column=3, padx=10, pady=10, sticky="w")

    Label(user_info_frame, text="Undertime Hours:", foreground='#0D47A1', bg='#E3F2FD', font=('Courier', 13)).grid(row=4, column=2, sticky="w")
    Entry(user_info_frame, textvariable=UNDERTIME_HOURS).grid(row=4, column=3, padx=10, pady=10)

    # Gross Pay and Deductions
    Label(user_info_frame, text="Gross Pay :", foreground='#0D47A1', bg='#E3F2FD', font=('Courier', 13)).grid(row=8, column=0, sticky="w")
    Entry(user_info_frame, textvariable=GROSS_PAY).grid(row=8, column=1, padx=10, pady=10)

    Label(user_info_frame, text="SSS :", foreground='#0D47A1', bg='#E3F2FD', font=('Courier', 13)).grid(row=0, column=4, sticky="w")
    Entry(user_info_frame, textvariable=SSS).grid(row=0, column=5, padx=10, pady=10)

    Label(user_info_frame, text="Philhealth :", foreground='#0D47A1', bg='#E3F2FD', font=('Courier', 13)).grid(row=1, column=4, sticky="w")
    Entry(user_info_frame, textvariable=PHILHEALTH).grid(row=1, column=5, sticky="we", padx=10, pady=10)

    Label(user_info_frame, text="Pag-ibig :", foreground='#0D47A1', bg='#E3F2FD', font=('Courier', 13)).grid(row=2, column=4, sticky="w")
    Entry(user_info_frame, textvariable=PAGIBIG).grid(row=2, column=5, sticky="we", padx=10, pady=10)

    Label(user_info_frame, text="Total Deduction :", foreground='#0D47A1', bg='#E3F2FD', font=('Courier', 13)).grid(row=3, column=4, sticky="w")
    Entry(user_info_frame, textvariable=TOTAL_DEDUC).grid(row=3, column=5, sticky="we", padx=10, pady=10)

    Label(user_info_frame, text="Netpay :", foreground='#0D47A1', bg='#E3F2FD', font=('Courier', 13)).grid(row=4, column=4, sticky="w")
    Entry(user_info_frame, textvariable=NETPAY).grid(row=4, column=5, sticky="we", padx=10, pady=10)

    # Buttons Frame
    reg_button_info_frame = LabelFrame(signup_frame, text="", foreground='black', bg='#E3F2FD')  # Light Blue background
    reg_button_info_frame.grid(row=1, column=0, sticky="news", padx=30, pady=15)

    Button(reg_button_info_frame, text="Submit", foreground='#FFFFFF', bg='#1976D2', font=('Courier', 13),
        command=submit_payroll, width=20).grid(row=0, column=2, sticky="news", pady=10, padx=20)

    Button(reg_button_info_frame, text="Calculate", foreground='#FFFFFF', bg='#1976D2', font=('Courier', 13),
        command=calculate_deductions, width=20).grid(row=0, column=4, sticky="news", pady=10, padx=20)

    search_info_frame = LabelFrame(signup_frame, text="", foreground='white', bg='#E3F2FD')  # Light Blue background
    search_info_frame.grid(row=2, column=0, sticky="news", padx=20, pady=10)

    TableMargin = Frame(signup_frame)
    TableMargin.grid(row=4, column=0, sticky="news", padx=20, pady=10)

    # TABLES (MAIN)
    scrollbarx = Scrollbar(TableMargin, orient=HORIZONTAL)
    scrollbary = Scrollbar(TableMargin, orient=VERTICAL)
    tree = ttk.Treeview(TableMargin,
                        columns=(
                            "Employee_Id", "Employee_No", "Employee_Name", "Last_Name", "Sex", "Address", "Age",
                            "Contact", "Rate"), height=5,
                        selectmode="extended", yscrollcommand=scrollbary.set, xscrollcommand=scrollbarx.set)
    scrollbary.config(command=tree.yview)
    scrollbary.pack(side=RIGHT, fill=Y)
    scrollbarx.config(command=tree.xview)
    scrollbarx.pack(side=BOTTOM, fill=X)
    tree.heading('Employee_Id', text="Employee Id.", anchor=W)
    tree.heading('Employee_No', text="Employee No.", anchor=W)
    tree.heading('Employee_Name', text="Employee Name", anchor=W)
    tree.heading('Last_Name', text="Last Name", anchor=W)
    tree.heading('Sex', text="Sex", anchor=W)
    tree.heading('Address', text="Address", anchor=W)
    tree.heading('Age', text="Age", anchor=W)
    tree.heading('Contact', text="Contact", anchor=W)
    tree.heading('Rate', text="Rate", anchor=W)
    tree.column('#0', stretch=NO, minwidth=0, width=0)
    tree.column('#1', stretch=NO, minwidth=0, width=0)
    tree.column('#2', stretch=NO, minwidth=0, width=90)
    tree.column('#3', stretch=NO, minwidth=0, width=110)
    tree.column('#4', stretch=NO, minwidth=0, width=100)
    tree.column('#5', stretch=NO, minwidth=0, width=0)
    tree.column('#6', stretch=NO, minwidth=0, width=0)
    tree.column('#7', stretch=NO, minwidth=0, width=0)
    tree.column('#8', stretch=NO, minwidth=0, width=0)
    tree.column('#9', stretch=NO, minwidth=0, width=110)

    tree.pack()
    tree.bind('<Double-Button-1>', OnSelected)
    reg_search_callback()

    exit_reg_delete_button = Button(signup_frame, text="Exit", foreground='#FFFFFF', bg='#1976D2', command=reg_window.destroy, width=20)  # Medium Blue button
    exit_reg_delete_button.grid(row=5, column=0, padx=20, pady=10)

def payroll_list():
    """
    Display the list of payroll records.
    """
    payroll_window = Toplevel()
    payroll_window.title("Payroll Management System")
    
    # Center the window
    window_width = 1100
    window_height = 800
    screen_width = payroll_window.winfo_screenwidth()
    screen_height = payroll_window.winfo_screenheight()
    x = (screen_width - window_width) // 2
    y = (screen_height - window_height) // 2
    payroll_window.geometry(f"{window_width}x{window_height}+{x}+{y}")
    
    # Main container to manage layout
    main_container = Frame(payroll_window)
    main_container.pack(fill=BOTH, expand=True)
    
    # Main title frame
    title_frame = Frame(main_container, bg='#E3F2FD', height=60)
    title_frame.pack(fill=X, pady=0)
    title_frame.pack_propagate(False)
    
    title_label = Label(title_frame, 
                       text="PAYROLL RECORDS",
                       font=('Arial', 16, 'bold'),
                       bg='#E3F2FD',
                       fg='#0D47A1')
    title_label.pack(pady=15)
    
    # Search frame with improved styling
    search_frame = Frame(main_container, bg='#FFFFFF', relief=RIDGE, bd=1)
    search_frame.pack(pady=10, padx=20, fill=X)
    
    # Date range selection with better styling
    date_frame = LabelFrame(search_frame, text="Date Range", bg='#FFFFFF', fg='#666666', font=('Arial', 9))
    date_frame.pack(side=LEFT, padx=10, pady=10)
    
    Label(date_frame, text="From:", bg='#FFFFFF').pack(side=LEFT, padx=5)
    from_cal = DateEntry(date_frame, width=12, background='#1976D2',
                        foreground='white', borderwidth=2,
                        font=('Arial', 9))
    from_cal.pack(side=LEFT, padx=5)
    
    Label(date_frame, text="To:", bg='#FFFFFF').pack(side=LEFT, padx=5)
    to_cal = DateEntry(date_frame, width=12, background='#1976D2',
                      foreground='white', borderwidth=2,
                      font=('Arial', 9))
    to_cal.pack(side=LEFT, padx=5)
    
    # Search entry with improved styling
    search_var = StringVar()
    search_entry = Entry(search_frame, textvariable=search_var,
                        width=30, font=('Arial', 10),
                        relief=SOLID, bd=1)
    search_entry.pack(side=LEFT, padx=20)
    
    search_label = Label(search_frame, 
                        text="Search by Employee No, First Name, or Last Name",
                        font=('Arial', 9),
                        bg='#FFFFFF',
                        fg='#666666')
    search_label.pack(side=LEFT, padx=5)
    
    # Create tree frame with improved styling
    tree_frame = Frame(main_container, bg='#FFFFFF', relief=RIDGE, bd=1)
    tree_frame.pack(pady=(5, 10), padx=20, fill=BOTH, expand=True)
    
    # Tree container for better organization
    tree_container = Frame(tree_frame, bg='#FFFFFF', padx=10, pady=10)
    tree_container.pack(fill=BOTH, expand=True)
    
    # Add scrollbars with modern styling
    vsb = ttk.Scrollbar(tree_container, orient="vertical")
    vsb.pack(side=RIGHT, fill=Y)
    
    hsb = ttk.Scrollbar(tree_container, orient="horizontal")
    hsb.pack(side=BOTTOM, fill=X)
    
    # Configure treeview with modern styling
    style = ttk.Style()
    style.configure("Custom.Treeview.Heading",
                   font=('Arial', 10, 'bold'),
                   foreground='#1976D2',
                   background='#E3F2FD',
                   padding=8)
    style.configure("Custom.Treeview",
                   font=('Arial', 9),
                   rowheight=18,
                   background='#FFFFFF',
                   fieldbackground='#FFFFFF',
                   foreground='#333333')
    style.map('Custom.Treeview',
              background=[('selected', '#1976D2')],
              foreground=[('selected', '#FFFFFF')])
    
    # Configure treeview
    tree = ttk.Treeview(tree_container,
                       style="Custom.Treeview",
                       columns=(
                           'ID', 'Employee No', 'First Name', 'Last Name', 'Rate',
                           'Hours Worked', 'OT Hours', 'OT Pay', 'UT Hours', 'Late Deduction',
                           'Gross Pay', 'Cash Advance', 'SSS', 'PhilHealth', 'Pag-IBIG',
                           'Total Deductions', 'Net Pay', 'Date'
                       ),
                       show='headings',
                       height=20)
    
    # Configure scrollbars
    tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
    vsb.configure(command=tree.yview)
    hsb.configure(command=tree.xview)
    
    # Pack the tree
    tree.pack(fill=BOTH, expand=True)
    
    # Configure column headings with consistent styling
    headings = {
        'ID': ['ID', 50],
        'Employee No': ['Employee No.', 100],
        'First Name': ['First Name', 120],
        'Last Name': ['Last Name', 120],
        'Rate': ['Rate/Hour', 80],
        'Hours Worked': ['Hours', 70],
        'OT Hours': ['OT Hours', 70],
        'OT Pay': ['OT Pay', 80],
        'UT Hours': ['UT Hours', 70],
        'Late Deduction': ['Late Deduction', 100],
        'Gross Pay': ['Gross Pay', 100],
        'Cash Advance': ['Cash Advance', 100],
        'SSS': ['SSS', 90],
        'PhilHealth': ['PhilHealth', 90],
        'Pag-IBIG': ['Pag-IBIG', 90],
        'Total Deductions': ['Total Deductions', 120],
        'Net Pay': ['Net Pay', 100],
        'Date': ['Date', 90]
    }
    
    # Apply the configurations
    for column, (heading, width) in headings.items():
        tree.heading(column, text=heading, anchor=CENTER)
        tree.column(column, width=width, anchor=CENTER, minwidth=width)
        
    def search_records(*args):
        search_text = search_var.get()
        
        # Clear existing items
        for item in tree.get_children():
            tree.delete(item)
            
        try:
            conn = sqlite3.connect("payroll_system.db")
            cursor = conn.cursor()
            
            query = """
                SELECT p.id, p.employee_no, e.firstname, e.lastname,
                       p.rate, p.number_hours_work, p.overtime_hours, p.overtime_pay,
                       p.undertime_hours, p.late_deduction,
                       p.gross_pay, p.cash_advance, p.sss, p.philhealth, p.pagibig,
                       p.total_deduc, p.netpay, p.date
                FROM TblPayroll p
                JOIN TblEmployees e ON p.employee_no = e.employee_no
                WHERE e.firstname LIKE ? OR e.lastname LIKE ? 
                      OR p.employee_no LIKE ? OR p.date LIKE ?
                ORDER BY p.date DESC, e.lastname, e.firstname
            """
            search_pattern = f"%{search_text}%"
            
            cursor.execute(query, (search_pattern, search_pattern, search_pattern, search_pattern))
            records = cursor.fetchall()
            
            for row in records:
                tree.insert("", "end", values=row)
                
        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"Database error in search: {str(e)}")
            logging.error(f"Database error in search: {e}")
        finally:
            if 'cursor' in locals():
                cursor.close()
            if 'conn' in locals():
                conn.close()

    def delete_payroll_record():
        """Delete the selected payroll record."""
        selected_items = tree.selection()
        if not selected_items:
            messagebox.showwarning("Warning", "Please select a payroll record to delete.")
            return
            
        if messagebox.askyesno("Confirm Delete", "Are you sure you want to delete the selected payroll record(s)?"):
            try:
                conn = sqlite3.connect("payroll_system.db")
                cursor = conn.cursor()
                
                for item in selected_items:
                    record_id = tree.item(item)['values'][0]  # Get the ID from the first column
                    cursor.execute("DELETE FROM TblPayroll WHERE id = ?", (record_id,))
                
                conn.commit()
                messagebox.showinfo("Success", "Payroll record(s) deleted successfully!")
                search_records()  # Refresh the list
                
            except sqlite3.Error as e:
                messagebox.showerror("Error", f"Failed to delete record: {str(e)}")
                logging.error(f"Error deleting payroll record: {e}")
            finally:
                if cursor:
                    cursor.close()
                if conn:
                    conn.close()

    search_var.trace('w', search_records)
    
    # Button frame at the bottom
    button_frame = Frame(main_container, bg='#F5F5F5', height=50)
    button_frame.pack(side=BOTTOM, fill=X, padx=20, pady=10)
    button_frame.pack_propagate(False)

    # Preview button
    preview_button = Button(button_frame, 
                          text="Preview Payslip", 
                          foreground='white',
                          bg='#1976D2', 
                          width=15,
                          height=1,
                          font=('Helvetica', 10, 'bold'),
                          command=lambda: on_preview_selected(None))
    preview_button.pack(side=LEFT, padx=5, pady=8)

    # Export button
    export_button = Button(button_frame, 
                         text="Export to Excel", 
                         foreground='white',
                         bg='#1976D2', 
                         width=15,
                         height=1,
                         font=('Helvetica', 10, 'bold'),
                         command=lambda: export_to_excel(tree))
    export_button.pack(side=LEFT, padx=5, pady=8)

    # Delete button
    delete_button = Button(button_frame, 
                         text="Delete", 
                         foreground='white',
                         bg='#E53935',  # Red color for delete
                         width=15,
                         height=1,
                         font=('Helvetica', 10, 'bold'),
                         command=delete_payroll_record)
    delete_button.pack(side=LEFT, padx=5, pady=8)

    # Refresh button
    refresh_button = Button(button_frame, 
                          text="Refresh", 
                          foreground='white', 
                          bg='#1976D2', 
                          width=15,
                          height=1,
                          font=('Helvetica', 10, 'bold'),
                          command=lambda: search_records())
    refresh_button.pack(side=LEFT, padx=5, pady=8)

    # Close button
    close_button = Button(button_frame, 
                         text="Close", 
                         foreground='white', 
                         bg='#1976D2', 
                         width=15,
                         height=1,
                         font=('Helvetica', 10, 'bold'),
                         command=payroll_window.destroy)
    close_button.pack(side=RIGHT, padx=5, pady=8)

    # Initial load of records
    search_records()
    
    def on_preview_selected(event=None):
        selected_item = tree.selection()
        if not selected_item:
            messagebox.showwarning("Warning", "Please select a payroll record to preview.")
            return
            
        # Get the selected payroll ID
        payroll_id = tree.item(selected_item[0])['values'][0]
        
        try:
            conn = sqlite3.connect("payroll_system.db")
            cursor = conn.cursor()
            
            query = """
                SELECT p.*, e.firstname, e.lastname, e.employee_no,
                       e.department, e.position, e.employment_status
                FROM TblPayroll p
                JOIN TblEmployees e ON p.employee_no = e.employee_no
                WHERE p.id = ?
            """
            cursor.execute(query, (payroll_id,))
            payroll_data = cursor.fetchone()
            
            if payroll_data:
                preview_window = Toplevel()
                preview_window.title("Payroll Preview")
                preview_window.geometry("800x900")
                preview_window.configure(bg='#f0f0f0')
                
                # Create scrollable canvas
                canvas = Canvas(preview_window, bg='#f0f0f0')
                scrollbar = ttk.Scrollbar(preview_window, orient="vertical", command=canvas.yview)
                scrollable_frame = Frame(canvas, bg='#f0f0f0')
                
                scrollable_frame.bind(
                    "<Configure>",
                    lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
                )
                
                canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
                canvas.configure(yscrollcommand=scrollbar.set)
                
                # Create main container with white background and shadow effect
                main_container = Frame(scrollable_frame, bg='white', bd=1, relief=SOLID)
                main_container.pack(fill=BOTH, expand=True, padx=40, pady=20)
                
                # Fonts
                font_normal = ('Segoe UI', 10)
                font_bold = ('Segoe UI', 10, 'bold')
                font_title = ('Segoe UI', 16, 'bold')
                font_subtitle = ('Segoe UI', 12, 'bold')
                
                # Title Section with gradient background
                title_frame = Frame(main_container, bg='#1976D2', height=80)
                title_frame.pack(fill=X)
                title_frame.pack_propagate(False)
                
                Label(title_frame, text="PAYSLIP", font=font_title, bg='#1976D2', fg='white').pack(pady=(20,0))
                Label(title_frame, text=f"Pay Period: {payroll_data[17]}", font=font_subtitle, bg='#1976D2', fg='white').pack()
                
                # Company Information with subtle background
                company_frame = Frame(main_container, bg='#f8f9fa', padx=20, pady=10)
                company_frame.pack(fill=X)
                Label(company_frame, text="PAYROLL MANAGEMENT SYSTEM", font=font_subtitle, bg='#f8f9fa').pack(anchor=W)
                Label(company_frame, text="Camp IV, Talisay City, Cebu - 6045", font=font_normal, bg='#f8f9fa').pack(anchor=W)
                Label(company_frame, text="(123) 456-7890 | payslip@company.com", font=font_normal, bg='#f8f9fa').pack(anchor=W)
                
                # Separator
                ttk.Separator(main_container, orient='horizontal').pack(fill=X, padx=20, pady=10)
                
                # Employee Information with grid layout
                emp_frame = Frame(main_container, bg='white', padx=20, pady=10)
                emp_frame.pack(fill=X)
                
                # Employee info in 2 columns
                left_emp = Frame(emp_frame, bg='white')
                left_emp.pack(side=LEFT, expand=True, fill=BOTH)
                right_emp = Frame(emp_frame, bg='white')
                right_emp.pack(side=LEFT, expand=True, fill=BOTH)
                
                # Left column
                Label(left_emp, text="Employment Details", font=font_subtitle, bg='white', fg='#1976D2').pack(anchor=W, pady=(0,10))
                Label(left_emp, text=f"Name: {payroll_data[-6]} {payroll_data[-5]}", font=font_normal, bg='white').pack(anchor=W)
                Label(left_emp, text=f"ID: {payroll_data[1]}", font=font_normal, bg='white').pack(anchor=W)
                Label(left_emp, text=f"Position: {payroll_data[-3]}", font=font_normal, bg='white').pack(anchor=W)
                
                # Right column
                Label(right_emp, text="", font=font_subtitle, bg='white', fg='#1976D2').pack(anchor=W, pady=(0,10))
                Label(right_emp, text=f"Department: {payroll_data[-4]}", font=font_normal, bg='white').pack(anchor=W)
                Label(right_emp, text=f"Status: {payroll_data[-1]}", font=font_normal, bg='white').pack(anchor=W)
                Label(right_emp, text=f"Pay Date: {datetime.now().strftime('%Y-%m-%d')}", font=font_normal, bg='white').pack(anchor=W)
                
                ttk.Separator(main_container, orient='horizontal').pack(fill=X, padx=20, pady=10)
                
                # Earnings Section with card-like design
                earnings_frame = Frame(main_container, bg='white', padx=20, pady=10)
                earnings_frame.pack(fill=X)
                
                Label(earnings_frame, text="EARNINGS", font=font_subtitle, bg='white', fg='#2E7D32').pack(anchor=W)
                
                # Create a frame with border for earnings details
                earnings_detail = Frame(earnings_frame, bg='white', bd=1, relief=SOLID)
                earnings_detail.pack(fill=X, pady=10)
                
                basic_pay = payroll_data[4] * payroll_data[5]
                earnings_items = [
                    ("Basic Salary", basic_pay),
                    ("Overtime Pay", payroll_data[7]),
                    ("Allowances", 0.00),
                    ("Holiday/Rest Day Pay", 0.00),
                    ("Bonuses/Incentives", 0.00),
                    ("Other Earnings", 0.00)
                ]
                
                for i, (label, amount) in enumerate(earnings_items):
                    item_frame = Frame(earnings_detail, bg='white' if i % 2 == 0 else '#f8f9fa')
                    item_frame.pack(fill=X)
                    Label(item_frame, text=label, font=font_normal, bg=item_frame['bg'], width=25, anchor='w').pack(side=LEFT, padx=10, pady=5)
                    Label(item_frame, text=f"PHP {amount:,.2f}", font=font_normal, bg=item_frame['bg']).pack(side=RIGHT, padx=10, pady=5)
                
                total_frame = Frame(earnings_detail, bg='#e8f5e9')
                total_frame.pack(fill=X)
                Label(total_frame, text="Total Earnings", font=font_bold, bg='#e8f5e9', width=25, anchor='w').pack(side=LEFT, padx=10, pady=5)
                Label(total_frame, text=f"PHP {payroll_data[10]:,.2f}", font=font_bold, bg='#e8f5e9').pack(side=RIGHT, padx=10, pady=5)
                
                # Deductions Section
                deductions_frame = Frame(main_container, bg='white', padx=20, pady=10)
                deductions_frame.pack(fill=X)
                
                Label(deductions_frame, text="DEDUCTIONS", font=font_subtitle, bg='white', fg='#C62828').pack(anchor=W)
                
                # Create a frame with border for deductions details
                deductions_detail = Frame(deductions_frame, bg='white', bd=1, relief=SOLID)
                deductions_detail.pack(fill=X, pady=10)
                
                deductions_items = [
                    ("SSS Contribution", payroll_data[12]),
                    ("PhilHealth", payroll_data[13]),
                    ("Pag-IBIG", payroll_data[14]),
                    ("Withholding Tax", 0.00),
                    ("Cash Advance / Loan", payroll_data[11]),
                    ("Other Deductions", payroll_data[9])
                ]
                
                for i, (label, amount) in enumerate(deductions_items):
                    item_frame = Frame(deductions_detail, bg='white' if i % 2 == 0 else '#f8f9fa')
                    item_frame.pack(fill=X)
                    Label(item_frame, text=label, font=font_normal, bg=item_frame['bg'], width=25, anchor='w').pack(side=LEFT, padx=10, pady=5)
                    Label(item_frame, text=f"PHP {amount:,.2f}", font=font_normal, bg=item_frame['bg']).pack(side=RIGHT, padx=10, pady=5)
                
                total_frame = Frame(deductions_detail, bg='#ffebee')
                total_frame.pack(fill=X)
                Label(total_frame, text="Total Deductions", font=font_bold, bg='#ffebee', width=25, anchor='w').pack(side=LEFT, padx=10, pady=5)
                Label(total_frame, text=f"PHP {payroll_data[15]:,.2f}", font=font_bold, bg='#ffebee').pack(side=RIGHT, padx=10, pady=5)
                
                # Net Pay Section with highlighted background
                net_pay_frame = Frame(main_container, bg='#1976D2', padx=20, pady=15)
                net_pay_frame.pack(fill=X, pady=20)
                Label(net_pay_frame, text="NET PAY", font=font_subtitle, bg='#1976D2', fg='white').pack(side=LEFT, padx=10)
                Label(net_pay_frame, text=f"PHP {payroll_data[16]:,.2f}", font=('Segoe UI', 14, 'bold'), bg='#1976D2', fg='white').pack(side=RIGHT, padx=10)
                
                # Additional Information
                info_frame = Frame(main_container, bg='white', padx=20, pady=10)
                info_frame.pack(fill=X)
                
                # Bank info and payslip number with subtle background
                bank_frame = Frame(info_frame, bg='#f8f9fa', bd=1, relief=SOLID)
                bank_frame.pack(fill=X, pady=10)
                Label(bank_frame, text="Bank: [Not Available]", font=font_normal, bg='#f8f9fa', padx=10, pady=5).pack(anchor=W)
                Label(bank_frame, text="Account No.: [Not Available]", font=font_normal, bg='#f8f9fa', padx=10, pady=5).pack(anchor=W)
                Label(bank_frame, text=f"Payslip No.: {payroll_data[0]:08d}", font=font_normal, bg='#f8f9fa', padx=10, pady=5).pack(anchor=W)
                
                # Signature Lines with bottom border
                sig_frame = Frame(main_container, bg='white', padx=20, pady=20)
                sig_frame.pack(fill=X)
                
                left_sig = Frame(sig_frame, bg='white')
                left_sig.pack(side=LEFT, expand=True, padx=10)
                right_sig = Frame(sig_frame, bg='white')
                right_sig.pack(side=LEFT, expand=True, padx=10)
                
                Label(left_sig, text="________________", font=font_normal, bg='white').pack()
                Label(left_sig, text="Prepared by", font=font_normal, bg='white').pack()
                
                Label(right_sig, text="________________", font=font_normal, bg='white').pack()
                Label(right_sig, text="Approved by", font=font_normal, bg='white').pack()
                
                # Date Generated
                date_frame = Frame(main_container, bg='#f8f9fa', padx=20, pady=10)
                date_frame.pack(fill=X)
                Label(date_frame, text=f"Date Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 
                      font=font_normal, bg='#f8f9fa').pack(side=RIGHT)
                
                # Buttons frame with modern styling
                button_frame = Frame(preview_window, bg='#f0f0f0')
                button_frame.pack(fill=X, padx=40, pady=15)
                
                def save_as_pdf():
                    try:
                        filename = filedialog.asksaveasfilename(
                            initialfile=f'payslip_{payroll_data[1]}_{payroll_data[17]}.pdf',
                            defaultextension=".pdf",
                            filetypes=[("PDF files", "*.pdf")]
                        )
                        if filename:
                            # Create the PDF document
                            doc = SimpleDocTemplate(
                                filename,
                                pagesize=letter,
                                rightMargin=72,
                                leftMargin=72,
                                topMargin=72,
                                bottomMargin=72
                            )
                            
                            # Container for the 'Flowable' objects
                            elements = []
                            
                            # Styles
                            styles = getSampleStyleSheet()
                            title_style = ParagraphStyle(
                                'CustomTitle',
                                parent=styles['Heading1'],
                                fontSize=16,
                                alignment=1,  # Center alignment
                                spaceAfter=30
                            )
                            
                            header_style = ParagraphStyle(
                                'CustomHeader',
                                parent=styles['Heading2'],
                                fontSize=12,
                                textColor=colors.HexColor('#1976D2'),
                                spaceAfter=20
                            )
                            
                            normal_style = styles["Normal"]
                            
                            # Title
                            elements.append(Paragraph("PAYSLIP", title_style))
                            
                            # Company Information
                            company_data = [
                                ["Employer:", "PAYROLL MANAGEMENT SYSTEM"],
                                ["Address:", "Camp IV,Talisay City, Cebu - 6045"],
                                ["Contact:", "(123) 456-7890 / payslip@company.com"]
                            ]
                            company_table = Table(company_data, colWidths=[2*inch, 4*inch])
                            company_table.setStyle(TableStyle([
                                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                                ('FONTSIZE', (0, 0), (-1, -1), 10),
                                ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                            ]))
                            elements.append(company_table)
                            elements.append(Spacer(1, 20))
                            
                            # Employee Information
                            elements.append(Paragraph("Employee Information", header_style))
                            emp_data = [
                                ["Employee Name:", f"{payroll_data[-6]} {payroll_data[-5]}"],
                                ["Employee ID:", payroll_data[1]],
                                ["Position:", payroll_data[-3]],
                                ["Department:", payroll_data[-4]],
                                ["Pay Period:", payroll_data[17]],
                                ["Pay Date:", datetime.now().strftime('%Y-%m-%d')]
                            ]
                            emp_table = Table(emp_data, colWidths=[2*inch, 4*inch])
                            emp_table.setStyle(TableStyle([
                                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                                ('FONTSIZE', (0, 0), (-1, -1), 10),
                                ('GRID', (0, 0), (-1, -1), 0.25, colors.grey),
                                ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                                ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                            ]))
                            elements.append(emp_table)
                            elements.append(Spacer(1, 20))
                            
                            # Earnings
                            elements.append(Paragraph("Earnings", header_style))
                            basic_pay = payroll_data[4] * payroll_data[5]
                            earnings_data = [
                                ["Description", "Amount"],
                                ["Basic Salary", f"PHP {basic_pay:,.2f}"],
                                ["Overtime Pay", f"PHP {payroll_data[7]:,.2f}"],
                                ["Allowances", "PHP 0.00"],
                                ["Holiday/Rest Day Pay", "PHP 0.00"],
                                ["Bonuses/Incentives", "PHP 0.00"],
                                ["Other Earnings", "PHP 0.00"],
                                ["Total Earnings", f"PHP {payroll_data[10]:,.2f}"]
                            ]
                            earnings_table = Table(earnings_data, colWidths=[3*inch, 3*inch])
                            earnings_table.setStyle(TableStyle([
                                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                                ('ALIGN', (1, 0), (1, -1), 'RIGHT'),
                                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                                ('FONTSIZE', (0, 0), (-1, -1), 10),
                                ('GRID', (0, 0), (-1, -1), 0.25, colors.grey),
                                ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                                ('BACKGROUND', (0, -1), (-1, -1), colors.lightgrey),
                                ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                            ]))
                            elements.append(earnings_table)
                            elements.append(Spacer(1, 20))
                            
                            # Deductions
                            elements.append(Paragraph("Deductions", header_style))
                            deductions_data = [
                                ["Description", "Amount"],
                                ["SSS Contribution", f"PHP {payroll_data[12]:,.2f}"],
                                ["PhilHealth", f"PHP {payroll_data[13]:,.2f}"],
                                ["Pag-IBIG", f"PHP {payroll_data[14]:,.2f}"],
                                ["Withholding Tax", "PHP 0.00"],
                                ["Cash Advance / Loan", f"PHP {payroll_data[11]:,.2f}"],
                                ["Other Deductions", f"PHP {payroll_data[9]:,.2f}"],
                                ["Total Deductions", f"PHP {payroll_data[15]:,.2f}"]
                            ]
                            deductions_table = Table(deductions_data, colWidths=[3*inch, 3*inch])
                            deductions_table.setStyle(TableStyle([
                                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                                ('ALIGN', (1, 0), (1, -1), 'RIGHT'),
                                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                                ('FONTSIZE', (0, 0), (-1, -1), 10),
                                ('GRID', (0, 0), (-1, -1), 0.25, colors.grey),
                                ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                                ('BACKGROUND', (0, -1), (-1, -1), colors.lightgrey),
                                ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                            ]))
                            elements.append(deductions_table)
                            elements.append(Spacer(1, 20))
                            
                            # Net Pay
                            net_pay_data = [["NET PAY:", f"PHP {payroll_data[16]:,.2f}"]]
                            net_pay_table = Table(net_pay_data, colWidths=[3*inch, 3*inch])
                            net_pay_table.setStyle(TableStyle([
                                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                                ('ALIGN', (1, 0), (1, -1), 'RIGHT'),
                                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
                                ('FONTSIZE', (0, 0), (-1, -1), 12),
                                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1976D2')),
                                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                                ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                            ]))
                            elements.append(net_pay_table)
                            elements.append(Spacer(1, 30))
                            
                            # Signature Lines
                            sig_data = [
                                ["________________", "________________"],
                                ["Prepared by", "Approved by"]
                            ]
                            sig_table = Table(sig_data, colWidths=[3*inch, 3*inch])
                            sig_table.setStyle(TableStyle([
                                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                                ('FONTSIZE', (0, 0), (-1, -1), 10),
                                ('TOPPADDING', (0, 1), (-1, 1), 5),
                            ]))
                            elements.append(sig_table)
                            elements.append(Spacer(1, 20))
                            
                            # Footer with date generated and payslip number
                            footer_text = f"Date Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Payslip No.: {payroll_data[0]:08d}"
                            elements.append(Paragraph(footer_text, normal_style))
                            
                            # Build the PDF document
                            doc.build(elements)
                            messagebox.showinfo("Success", f"PDF has been saved to:\n{filename}")
                            
                    except Exception as e:
                        messagebox.showerror("Error", f"Failed to save PDF: {str(e)}")
                
                def print_payslip():
                    try:
                        messagebox.showinfo("Print", "Sending to printer...")
                        # Implement actual printing functionality here
                    except Exception as e:
                        messagebox.showerror("Error", f"Failed to print: {str(e)}")
                
                # Modern styled buttons
                button_styles = [
                    ("Print Payslip", print_payslip, '#2196F3', '#1976D2'),
                    ("Save as PDF", save_as_pdf, '#4CAF50', '#388E3C'),
                    ("Close", preview_window.destroy, '#F44336', '#D32F2F')
                ]
                
                for text, command, color, hover_color in button_styles:
                    btn = Button(button_frame, text=text, command=command,
                               bg=color, fg='white', font=('Segoe UI', 10, 'bold'),
                               width=15, height=1, cursor='hand2', bd=0)
                    btn.pack(side=LEFT, padx=5)
                    
                    # Hover effects
                    btn.bind('<Enter>', lambda e, btn=btn, hc=hover_color: btn.configure(bg=hc))
                    btn.bind('<Leave>', lambda e, btn=btn, c=color: btn.configure(bg=c))
                
                # Pack scrollbar and canvas
                scrollbar.pack(side=RIGHT, fill=Y)
                canvas.pack(side=LEFT, fill=BOTH, expand=True)
                
                # Configure mousewheel scrolling
                def _on_mousewheel(event):
                    canvas.yview_scroll(int(-1*(event.delta/120)), "units")

                    # Configure mousewheel scrolling
                def _on_mousewheel(event):
                    canvas.yview_scroll(int(-1*(event.delta/120)), "units")

                def _bind_mousewheel(event=None):
                    canvas.bind_all("<MouseWheel>", _on_mousewheel)

                def _unbind_mousewheel(event=None):
                    canvas.unbind_all("<MouseWheel>")

                # Bind mousewheel when mouse enters the canvas
                canvas.bind('<Enter>', _bind_mousewheel)
                # Unbind mousewheel when mouse leaves the canvas
                canvas.bind('<Leave>', _unbind_mousewheel)

                # Unbind mousewheel when window is closed
                def on_closing():
                    _unbind_mousewheel()
                    preview_window.destroy()

                preview_window.protocol("WM_DELETE_WINDOW", on_closing)
                
                canvas.bind_all("<MouseWheel>", _on_mousewheel)
                       
        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"Database error in preview: {str(e)}")
            logging.error(f"Database error in preview: {e}")
        finally:
            if 'cursor' in locals():
                cursor.close()
            if 'conn' in locals():
                conn.close()

def get_user_role(username):
    """
    Get the role of a user from the database.
    
    Args:
        username (str): The username to look up
        
    Returns:
        str: The user's role ('admin', 'manager', or 'user')
    """
    try:
        with sqlite3.connect("payroll_system.db") as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT role FROM TblPassword WHERE username = ?", (username,))
            result = cursor.fetchone()
            return result[0] if result else 'user'  # Default to 'user' if not found
    except sqlite3.Error as e:
        logging.error(f"Error getting user role for {username}: {e}")
        return 'user'  # Default to 'user' on error

def menu_manage():
    """
    Display the system maintenance window for password management.
    """
    global current_session
    
    if not current_session or not current_session.username:
        messagebox.showerror("Error", "No active session. Please log in again.")
        return
        
    current_user_role = current_session.role  # Use role directly from session
    
    # Add debug print to check the user role
    print(f"Current user: {current_session.username}, Role: {current_session.role}")

    def on_enter(e):
        """Change button color on mouse enter"""
        button = e.widget
        button['background'] = button.hover_bg

    def on_leave(e):
        """Restore button color on mouse leave"""
        button = e.widget
        button['background'] = button.default_bg

    def validate_password_strength(password):
        """Validate the strength of a password."""
        if len(password) < 8:
            return False, "Password must be at least 8 characters"
        if not any(c.isupper() for c in password):
            return False, "Password must contain uppercase letter"
        if not any(c.islower() for c in password):
            return False, "Password must contain lowercase letter"
        if not any(c.isdigit() for c in password):
            return False, "Password must contain a number"
        return True, ""

    def register_account():
        """Register a new user account."""
        name = NAME_INFO.get()
        username = USERNAME_INFO.get()
        password = PASSWORD_INFO.get()
        email = EMAIL_INFO.get() if EMAIL_INFO.get() else ""
        role = ROLE_INFO.get()
        status = STATUS_INFO.get()

        if not all([name, username, password, role, status]):
            tkMessageBox.showwarning('', 'Please complete the required fields', icon="warning")
            return
        
        # Validate password strength
        is_valid, message = validate_password_strength(password)
        if not is_valid:
            tkMessageBox.showwarning('', message, icon="warning")
            return

        if len(username) > 14 or len(password) > 14:
            tkMessageBox.showwarning('', 'Username and password should not exceed 14 characters', icon="warning")
            return

        try:
            with sqlite3.connect("payroll_system.db") as conn:
                cursor = conn.cursor()
                
                # Check if username already exists
                cursor.execute("SELECT * FROM TblPassword WHERE username=?", (username,))
                if cursor.fetchone():
                    tkMessageBox.showwarning('', 'Username already exists!', icon="warning")
                    return

                # Hash the password
                hashed_password = hash_password(password)
                
                # Insert into TblPassword
                cursor.execute("""
                    INSERT INTO TblPassword (name, username, password, email, role, status) 
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (name, username, hashed_password, email, role, status))
                
                conn.commit()
                tkMessageBox.showinfo("Success", "Account registered successfully!")
                clear_fields()
                refresh_account_list()

        except sqlite3.Error as e:
            tkMessageBox.showerror("Database Error", f"An error occurred: {str(e)}")

    def update_account():
        """Update the selected account."""
        # Check if user is admin
        user_role = current_session.role
        if user_role != 'admin':
            tkMessageBox.showwarning(
                'Access Denied', 
                'Only administrators can update accounts!', 
                icon="warning"
            )
            return

        if not tree.selection():
            tkMessageBox.showwarning('', 'Please select an account first!', icon="warning")
            return

        password = PASSWORD_INFO.get()
        role = ROLE_INFO.get()
        status = STATUS_INFO.get()
        
        if not password:
            tkMessageBox.showwarning('', 'Please enter a new password', icon="warning")
            return

        # Validate password strength
        is_valid, message = validate_password_strength(password)
        if not is_valid:
            tkMessageBox.showwarning('', message, icon="warning")
            return

        try:
            with sqlite3.connect("payroll_system.db") as conn:
                cursor = conn.cursor()
                hashed_password = hash_password(password)
                cursor.execute(
                    "UPDATE TblPassword SET password=?, role=?, status=? WHERE employee_id=?", 
                    (hashed_password, role, status, employee_id)
                )
                conn.commit()
                tkMessageBox.showinfo("Success", "Account updated successfully!")
                
                # Log the update
                logger.info(f"Account updated by admin {current_session.username}: {USERNAME_INFO.get()}")
                
                clear_fields()
                refresh_account_list()

        except sqlite3.Error as e:
            tkMessageBox.showerror("Database Error", f"An error occurred: {str(e)}")

    def delete_account():
        """Delete the selected account."""
        # Check if user is admin
        if current_session.role != 'admin':
            messagebox.showwarning(
                'Access Denied', 
                'Only administrators can delete accounts!', 
                icon="warning"
            )
            return

        if not tree.selection():
            messagebox.showwarning('', 'Please select an account first!', icon="warning")
            return

        # Get the selected item
        selected_item = tree.selection()[0]
        username = tree.item(selected_item)['values'][2]  # Username is at index 2

        # Prevent deleting own account
        if username == current_session.username:
            messagebox.showwarning(
                'Warning', 
                'You cannot delete your own account!', 
                icon="warning"
            )
            return

        # Confirm deletion
        if not messagebox.askyesno('Confirm Delete', 
                                  'Are you sure you want to delete this account?',
                                  icon='warning'):
            return

        try:
            with sqlite3.connect("payroll_system.db") as conn:
                cursor = conn.cursor()
                
                # Check if this is the last admin account
                cursor.execute("SELECT COUNT(*) FROM TblPassword WHERE role='admin'")
                admin_count = cursor.fetchone()[0]
                
                cursor.execute("SELECT role FROM TblPassword WHERE username=?", (username,))
                user_role = cursor.fetchone()[0]
                
                if admin_count <= 1 and user_role == 'admin':
                    messagebox.showwarning(
                        'Warning',
                        'Cannot delete the last admin account!',
                        icon="warning"
                    )
                    return

                # Delete from TblPassword
                cursor.execute("DELETE FROM TblPassword WHERE username=?", (username,))
                
                # Delete associated records from login_audit
                cursor.execute("DELETE FROM login_audit WHERE username=?", (username,))
                
                # Delete from TblUser if exists
                cursor.execute("DELETE FROM TblUser WHERE username=?", (username,))
                
                # Update TblEmployees if exists (set username to NULL)
                cursor.execute("UPDATE TblEmployees SET username=NULL WHERE username=?", (username,))
                
                conn.commit()
                messagebox.showinfo("Success", "Account deleted successfully!")
                
                # Log the deletion
                logging.info(f"Account deleted by admin {current_session.username}: {username}")
                
                # Refresh the account list
                refresh_account_list()
                clear_fields()

        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"An error occurred: {str(e)}")
            logging.error(f"Error deleting account {username}: {str(e)}")

    def clear_fields():
        """Clear all input fields."""
        NAME_INFO.set("")
        USERNAME_INFO.set("")
        PASSWORD_INFO.set("")
        EMAIL_INFO.set("")
        ROLE_INFO.set("user")
        STATUS_INFO.set("active")

    def refresh_account_list(*args):
        """Refresh the account list in the treeview."""
        search_term = menu_reg_search_var.get().strip().lower()
        
        # Clear the treeview
        for item in tree.get_children():
            tree.delete(item)

        try:
            with sqlite3.connect("payroll_system.db") as conn:
                cursor = conn.cursor()
                
                # Modified query to include role and status
                query = """
                    SELECT employee_id, name, username, email, role, status 
                    FROM TblPassword 
                    WHERE LOWER(username) LIKE ? OR 
                          LOWER(name) LIKE ? OR 
                          LOWER(email) LIKE ?
                    ORDER BY name
                """
                search_pattern = f"%{search_term}%"
                cursor.execute(query, (search_pattern, search_pattern, search_pattern))
                
                for row in cursor.fetchall():
                    tree.insert("", "end", values=row)

        except sqlite3.Error as e:
            tkMessageBox.showerror("Database Error", f"An error occurred: {str(e)}")

    def selected(event):
        """Handle the selection of an account from the treeview."""
        if not tree.selection():
            return
            
        curItem = tree.focus()
        contents = tree.item(curItem)
        selectedItem = contents['values']
        global employee_id
        employee_id = selectedItem[0]
        
        NAME_INFO.set(selectedItem[1])
        USERNAME_INFO.set(selectedItem[2])
        EMAIL_INFO.set(selectedItem[3])
        ROLE_INFO.set(selectedItem[4])
        STATUS_INFO.set(selectedItem[5])
        PASSWORD_INFO.set("")  # Clear password field for security

    # Initialize variables
    NAME_INFO = StringVar()
    USERNAME_INFO = StringVar()
    PASSWORD_INFO = StringVar()
    EMAIL_INFO = StringVar()
    ROLE_INFO = StringVar(value='user')  # Default role
    STATUS_INFO = StringVar(value='active')  # Default status
    menu_reg_search_var = StringVar()

    # Create the main window
    menu_password_window = Toplevel()
    menu_password_window.title("Password Management")
    menu_password_window.configure(bg='#E3F2FD')
    width = 1200
    height = 800
    screen_width = menu_password_window.winfo_screenwidth()
    screen_height = menu_password_window.winfo_screenheight()
    x = ((screen_width / 2) - 500) - (width / 2)
    y = ((screen_height / 2) + 20) - (height / 2)
    menu_password_window.geometry("%dx%d+%d+%d" % (width, height, x, y))
    menu_password_window.resizable(False, False)

    # Create frames
    password_management_frame = Frame(menu_password_window, bg='#E3F2FD')
    password_management_frame.pack(expand=True, fill=BOTH, padx=20, pady=10)

    # Title Frame
    title_frame = Frame(password_management_frame, bg='#E3F2FD')
    title_frame.pack(fill=X, pady=(0, 10))
    Label(title_frame, text="Password Management System", 
          font=('Helvetica', 18, 'bold'), bg='#E3F2FD', 
          fg='#0D47A1').pack()

    # Form Frame
    form_frame = LabelFrame(password_management_frame, text="Account Information",
                           font=('Helvetica', 12, 'bold'), bg='#E3F2FD', 
                           fg='#0D47A1', padx=15, pady=10)
    form_frame.pack(fill=X, padx=10, pady=5)

    # Create a grid of labels and entries
    form_fields = [
        ("Name*:", NAME_INFO),
        ("Username*:", USERNAME_INFO),
        ("Password*:", PASSWORD_INFO),
        ("Email:", EMAIL_INFO),
        ("Role*:", ROLE_INFO, ['user', 'admin', 'manager']),
        ("Status*:", STATUS_INFO, ['active', 'inactive', 'suspended'])
    ]

    for idx, field in enumerate(form_fields):
        # Label
        Label(form_frame, text=field[0], 
              font=('Helvetica', 11), 
              bg='#E3F2FD', 
              fg='#0D47A1',
              width=12, 
              anchor='e').grid(row=idx, column=0, padx=5, pady=8)
        
        # Entry or Combobox
        if len(field) == 3:  # For Role and Status dropdowns
            combo = ttk.Combobox(form_frame, 
                               textvariable=field[1],
                               values=field[2],
                               state='readonly',
                               font=('Helvetica', 11),
                               width=25)
            combo.grid(row=idx, column=1, padx=5, pady=8, sticky='w')
            if not combo.get():
                combo.set(field[2][0])  # Set default value
        else:
            entry = Entry(form_frame, 
                         textvariable=field[1],
                         font=('Helvetica', 11),
                         width=28)
            entry.grid(row=idx, column=1, padx=5, pady=8, sticky='w')
            if field[0] == "Password*:":
                entry.config(show="*")

    # Password requirements
    req_frame = LabelFrame(password_management_frame, text="Password Requirements",
                          font=('Helvetica', 12, 'bold'), bg='#E3F2FD',
                          fg='#0D47A1', padx=15, pady=10)
    req_frame.pack(fill=X, padx=10, pady=5)

    requirements = [
        "• Minimum 8 characters",
        "• At least one uppercase letter",
        "• At least one lowercase letter",
        "• At least one number"
    ]

    for req in requirements:
        Label(req_frame, text=req,
              font=('Helvetica', 10),
              bg='#E3F2FD',
              fg='#666666').pack(anchor='w')

    # Buttons Frame
    button_frame = Frame(password_management_frame, bg='#E3F2FD')
    button_frame.pack(fill=X, padx=10, pady=10)

    # Button styles with updated roles
    button_styles = [
        {
            "text": "Register",
            "command": register_account,
            "bg": '#4CAF50',  # Green
            "hover_bg": '#45a049',  # Darker green
            "width": 20,
            "height": 2,
            "roles": ['admin']  # Only admin can register
        },
        {
            "text": "Update",
            "command": update_account,
            "bg": '#2196F3',  # Blue
            "hover_bg": '#1976D2',  # Darker blue
            "width": 20,
            "height": 2,
            "roles": ['admin']  # Only admin can update
        },
        {
            "text": "Delete",
            "command": delete_account,
            "bg": '#F44336',  # Red
            "hover_bg": '#D32F2F',  # Darker red
            "width": 20,
            "height": 2,
            "roles": ['admin']  # Only admin can delete
        },
        {
            "text": "Clear",
            "command": clear_fields,
            "bg": '#757575',  # Grey
            "hover_bg": '#616161',  # Darker grey
            "width": 20,
            "height": 2,
            "roles": ['admin', 'manager', 'user']  # Everyone can clear
        }
    ]

    user_role = current_session.role
    
    for btn_style in button_styles:
        # Only create button if user has permission
        if user_role in btn_style["roles"]:
            btn = Button(button_frame, 
                        text=btn_style["text"],
                        command=btn_style["command"],
                        font=('Helvetica', 12, 'bold'),
                        bg=btn_style["bg"],
                        fg='white',
                        width=btn_style["width"],
                        height=btn_style["height"],
                        cursor='hand2',
                        relief=RAISED,
                        bd=1)
            
            # Store colors for hover effect
            btn.default_bg = btn_style["bg"]
            btn.hover_bg = btn_style["hover_bg"]
            
            # Bind hover events
            btn.bind("<Enter>", on_enter)
            btn.bind("<Leave>", on_leave)
            
            btn.pack(side=LEFT, padx=10)

    # Search Frame
    search_frame = Frame(password_management_frame, bg='#E3F2FD')
    search_frame.pack(fill=X, padx=10, pady=5)

    Label(search_frame, text="Search:",
          font=('Helvetica', 11),
          bg='#E3F2FD',
          fg='#0D47A1').pack(side=LEFT, padx=5)

    Entry(search_frame,
          textvariable=menu_reg_search_var,
          font=('Helvetica', 11),
          width=40).pack(side=LEFT, padx=5)

    # Tree Frame
    tree_frame = Frame(password_management_frame, bg='#E3F2FD')
    tree_frame.pack(fill=BOTH, expand=True, padx=10, pady=5)

    # Scrollbars
    scrolly = ttk.Scrollbar(tree_frame, orient=VERTICAL)
    scrollx = ttk.Scrollbar(tree_frame, orient=HORIZONTAL)
    scrolly.pack(side=RIGHT, fill=Y)
    scrollx.pack(side=BOTTOM, fill=X)

    # Treeview
    tree = ttk.Treeview(tree_frame,
                        columns=("ID", "Name", "Username", "Email", "Role", "Status"),
                        show='headings',
                        height=10,  # Set a fixed height
                        yscrollcommand=scrolly.set,
                        xscrollcommand=scrollx.set)

    # Configure scrollbars
    scrolly.config(command=tree.yview)
    scrollx.config(command=tree.xview)

    # Configure columns
    columns = {
        "ID": ("ID", 80),
        "Name": ("Name", 150),
        "Username": ("Username", 120),
        "Email": ("Email", 200),
        "Role": ("Role", 100),
        "Status": ("Status", 100)
    }

    # Configure column headings and widths
    for col, (heading, width) in columns.items():
        tree.heading(col, text=heading, anchor=CENTER)
        tree.column(col, width=width, anchor=CENTER, minwidth=width)

    # Define style for the treeview
    style = ttk.Style()
    style.configure("Treeview.Heading",
                   font=('Arial', 10, 'bold'),
                   foreground='#1976D2',
                   background='#E3F2FD',
                   padding=5)
    style.configure("Treeview",
                   font=('Arial', 9),
                   rowheight=25,
                   background='#FFFFFF',
                   fieldbackground='#FFFFFF')
    
    # Configure alternating row colors
    style.map('Treeview',
             background=[('selected', '#1976D2')],
             foreground=[('selected', '#FFFFFF')])

    tree.pack(fill=BOTH, expand=True)
    tree.bind('<Double-Button-1>', selected)

    # Initial refresh of account list
    refresh_account_list()

    # Bind the search variable to the refresh function
    menu_reg_search_var.trace('w', refresh_account_list)

def menu_registration():
    """
    Display the employee registration window.
    """
    # Department-specific positions dictionary
    department_positions = {
        "Administration": [
            "Administrative Director",
            "Office Manager",
            "Executive Assistant",
            "Administrative Assistant",
            "Receptionist",
            "Office Coordinator",
            "Records Manager",
            "Facilities Manager"
        ],
        "Human Resources": [
            "HR Director",
            "HR Manager",
            "HR Specialist",
            "Recruitment Coordinator",
            "Training Coordinator",
            "Benefits Administrator",
            "HR Analyst",
            "Employee Relations Manager",
            "HR Assistant"
        ],
        "Finance": [
            "Finance Director",
            "Finance Manager",
            "Senior Accountant",
            "Financial Analyst",
            "Payroll Specialist",
            "Budget Analyst",
            "Tax Specialist",
            "Treasury Analyst",
            "Bookkeeper"
        ],
        "IT": [
            "IT Director",
            "IT Manager",
            "System Administrator",
            "Network Engineer",
            "Software Developer",
            "Database Administrator",
            "Security Specialist",
            "IT Support Specialist",
            "DevOps Engineer"
        ],
        "Building Maintenance": [
            "Maintenance Director",
            "Maintenance Manager",
            "Facilities Supervisor",
            "Building Engineer",
            "HVAC Technician",
            "Electrician",
            "Plumber",
            "General Maintenance Technician",
            "Maintenance Assistant",
            "Groundskeeper",
            "Carpenter",
            "Painter",
            "Utility Worker",
            "Janitor",
            "Custodian"
        ],
        "Facilities & Utilities": [
            "Facilities Director",
            "Utilities Manager",
            "Facilities Supervisor",
            "Utility Supervisor",
            "Senior Utility Worker",
            "Utility Technician",
            "Utility Worker",
            "Waste Management Specialist",
            "Energy Systems Operator",
            "Water Systems Technician",
            "Facilities Coordinator",
            "Utility Maintenance Worker",
            "Sanitation Worker",
            "Cleaning Supervisor",
            "Cleaning Staff"
        ]
    }

    reg_window = Toplevel()
    reg_window.title("Employee Registration")
    width = 1000
    height = 800
    screen_width = reg_window.winfo_screenwidth()
    screen_height = reg_window.winfo_screenheight()
    x = (screen_width/2) - (width/2)
    y = (screen_height/2) - (height/2)
    reg_window.geometry(f"{width}x{height}+{int(x)}+{int(y)}")
    reg_window.configure(bg='#E3F2FD')

    # Variables - make sure these are defined before any functions that use them
    EMPLOYEE_NO = StringVar()
    FIRSTNAME = StringVar()
    LASTNAME = StringVar()
    SEX = StringVar()  # Added this
    AGE = StringVar()
    ADDRESS = StringVar()
    CONTACT = StringVar()
    RATE_PER_HOUR = StringVar()
    DEPARTMENT = StringVar()
    POSITION = StringVar()
    EMPLOYMENT_STATUS = StringVar()
    DATE_HIRED = StringVar()
    EMAIL = StringVar()
    EMERGENCY_CONTACT = StringVar()
    EMERGENCY_RELATION = StringVar()
    SSS_NO = StringVar()
    PHILHEALTH_NO = StringVar()
    PAGIBIG_NO = StringVar()
    TIN_NO = StringVar()
    reg_search_var = StringVar()  # Added this line

    def update_positions(*args):
        """Update position options based on selected department"""
        selected_dept = DEPARTMENT.get()
        if selected_dept in department_positions:
            position_combobox['values'] = department_positions[selected_dept]
            if POSITION.get() not in department_positions[selected_dept]:
                POSITION.set('')  # Clear position if not in new department

    def validate_required_fields():
        """
        Validate the required fields in the registration form.
        """
        missing_fields = []
        
        # Create/configure styles for ttk widgets
        style = ttk.Style()
        style.configure('Normal.TCombobox', fieldbackground='white')
        style.configure('Required.TCombobox', fieldbackground='#FFE0E0')
        style.configure('Normal.TEntry', fieldbackground='white')
        style.configure('Required.TEntry', fieldbackground='#FFE0E0')

        def reset_widget_style(widget):
            """
            Reset the style of a widget to its normal state.
            """
            try:
                if isinstance(widget, ttk.Entry):
                    widget.configure(style='Normal.TEntry')
                elif isinstance(widget, Entry):
                    widget.configure(bg='white')
                    widget['highlightbackground'] = '#E3F2FD'
                    widget['highlightthickness'] = 1
                elif isinstance(widget, ttk.Combobox):
                    widget.configure(style='Normal.TCombobox')
                elif isinstance(widget, Radiobutton):
                    widget.configure(bg='white')
                elif isinstance(widget, Label):
                    pass  # Skip labels
                elif isinstance(widget, Frame):
                    for child in widget.winfo_children():
                        reset_widget_style(child)
            except tk.TclError:
                pass  # Skip widgets that don't support the requested configuration

        # Reset all widgets
        for frame in [personal_frame, employment_frame]:
            for widget in frame.winfo_children():
                reset_widget_style(widget)

        def highlight_widget(widget):
            """
            Highlight the widget if it is empty.
            """
            try:
                if isinstance(widget, ttk.Entry):
                    widget.configure(style='Required.TEntry')
                elif isinstance(widget, Entry):
                    widget.configure(bg='#FFE0E0')
                    widget['highlightbackground'] = '#FF0000'
                    widget['highlightthickness'] = 2
                elif isinstance(widget, ttk.Combobox):
                    widget.configure(style='Required.TCombobox')
                elif isinstance(widget, Radiobutton):
                    widget.configure(bg='#FFE0E0')
                elif isinstance(widget, Frame):
                    for child in widget.winfo_children():
                        highlight_widget(child)
            except tk.TclError:
                pass  # Skip widgets that don't support the requested configuration

        # Check required fields
        fields_to_check = [
            (EMPLOYEE_NO.get(), "Employee No", personal_frame),
            (FIRSTNAME.get(), "First Name", personal_frame),
            (LASTNAME.get(), "Last Name", personal_frame),
            (SEX.get(), "Sex", personal_frame),
            (AGE.get(), "Age", personal_frame),
            (ADDRESS.get(), "Address", personal_frame),
            (CONTACT.get(), "Contact", personal_frame),
            (DEPARTMENT.get(), "Department", employment_frame),
            (POSITION.get(), "Position", employment_frame),
            (EMPLOYMENT_STATUS.get(), "Status", employment_frame),
            (DATE_HIRED.get(), "Date Hired", employment_frame),
            (RATE_PER_HOUR.get(), "Rate/Hour", employment_frame)
        ]

        for value, field_name, frame in fields_to_check:
            if not value.strip():
                missing_fields.append(field_name)
                # Find the corresponding widget and highlight it
                for widget in frame.winfo_children():
                    if isinstance(widget, Label) and field_name in widget.cget('text'):
                        grid_info = widget.grid_info()
                        if grid_info:  # If widget is managed by grid
                            row = grid_info['row']
                            col = grid_info['column']
                            # Find the input widget in the next column
                            for w in frame.grid_slaves(row=row, column=col+1):
                                highlight_widget(w)

        if missing_fields:
            message = "Please fill in the following required fields:\n• " + "\n• ".join(missing_fields)
            messagebox.showwarning('Required Fields', message, icon="warning")
            return False
        return True

    def submit_registration():
        """
        Submit the registration form and save the employee data to the database.
        """
        if not validate_required_fields():
            return
            
        try:
            conn = sqlite3.connect("payroll_system.db")
            cursor = conn.cursor()
            
            # Check if employee number already exists
            cursor.execute("SELECT * FROM TblEmployees WHERE employee_no=?", (EMPLOYEE_NO.get(),))
            if cursor.fetchone():
                messagebox.showwarning('', 'Employee Number Already Exists!', icon="warning")
                return

            # Insert new employee
            cursor.execute("""
                INSERT INTO TblEmployees (
                    employee_no, firstname, lastname, sex, age, address, 
                    contact, rate_per_hour, department, position, 
                    employment_status, date_hired, email, 
                    emergency_contact, emergency_contact_relationship,
                    sss_no, philhealth_no, pagibig_no, tin_no
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                EMPLOYEE_NO.get(), FIRSTNAME.get(), LASTNAME.get(),
                SEX.get(), AGE.get(), ADDRESS.get(),
                CONTACT.get(), RATE_PER_HOUR.get(), DEPARTMENT.get(),
                POSITION.get(), EMPLOYMENT_STATUS.get(), DATE_HIRED.get(),
                EMAIL.get(), EMERGENCY_CONTACT.get(), EMERGENCY_RELATION.get(),
                SSS_NO.get(), PHILHEALTH_NO.get(), PAGIBIG_NO.get(), TIN_NO.get()
            ))
            
            conn.commit()
            messagebox.showinfo('Success', 'Employee Registration Successful')
            ClearField()
            reg_search_callback()
            
        except sqlite3.Error as e:
            messagebox.showerror('Error', f'Database Error: {str(e)}')
        finally:
            cursor.close()
            conn.close()

    def update_registration():
        """
        Update the registration form and save the employee data to the database.
        """
        if not validate_required_fields():
            return
            
        if not tree.selection():
            messagebox.showwarning('', 'Please Select an Employee to Update', icon="warning")
            return

        try:
            conn = sqlite3.connect("payroll_system.db")
            cursor = conn.cursor()
            
            # Get the selected item
            selected_item = tree.selection()[0]
            values = tree.item(selected_item)['values']
            
            cursor.execute("""
                UPDATE TblEmployees SET 
                    firstname=?, lastname=?, sex=?, age=?, address=?,
                    contact=?, department=?, position=?, employment_status=?,
                    date_hired=?, rate_per_hour=?, email=?,
                    emergency_contact=?, emergency_contact_relationship=?,
                    sss_no=?, philhealth_no=?, pagibig_no=?, tin_no=?
                WHERE employee_no=?
            """, (
                FIRSTNAME.get(), LASTNAME.get(), SEX.get(),
                AGE.get(), ADDRESS.get(), CONTACT.get(),
                DEPARTMENT.get(), POSITION.get(), EMPLOYMENT_STATUS.get(),
                DATE_HIRED.get(), RATE_PER_HOUR.get(), EMAIL.get(),
                EMERGENCY_CONTACT.get(), EMERGENCY_RELATION.get(),
                SSS_NO.get(), PHILHEALTH_NO.get(), PAGIBIG_NO.get(),
                TIN_NO.get(), EMPLOYEE_NO.get()
            ))
            
            conn.commit()
            messagebox.showinfo('Success', 'Employee Information Updated Successfully')
            ClearField()
            reg_search_callback()
            
        except sqlite3.Error as e:
            messagebox.showerror('Error', f'Database Error: {str(e)}')
        finally:
            cursor.close()
            conn.close()

    def ClearField():
        """
        Clear all fields in the registration form.
        """
        EMPLOYEE_NO.set("")
        FIRSTNAME.set("")
        LASTNAME.set("")
        SEX.set("")
        AGE.set("")
        ADDRESS.set("")
        CONTACT.set("")
        RATE_PER_HOUR.set("")
        DEPARTMENT.set("")
        POSITION.set("")
        EMPLOYMENT_STATUS.set("")
        DATE_HIRED.set("")
        EMAIL.set("")
        EMERGENCY_CONTACT.set("")
        EMERGENCY_RELATION.set("")
        SSS_NO.set("")
        PHILHEALTH_NO.set("")
        PAGIBIG_NO.set("")
        TIN_NO.set("")

    def deletedata():
        """
        Delete an employee record from the database.
        """
        if not tree.selection():
            messagebox.showwarning('', 'Please Select an Employee to Delete', icon="warning")
            return
            
        result = messagebox.askquestion(
            'Confirm', 'Are you sure you want to delete this record?', icon="warning")
        
        if result == 'yes':
            try:
                conn = sqlite3.connect("payroll_system.db")
                cursor = conn.cursor()
                
                cursor.execute("DELETE FROM TblEmployees WHERE employee_no=?", (EMPLOYEE_NO.get(),))
                conn.commit()
                
                messagebox.showinfo('Success', 'Employee Record Deleted Successfully')
                ClearField()
                reg_search_callback()
                
            except sqlite3.Error as e:
                messagebox.showerror('Error', f'Database Error: {str(e)}')
            finally:
                cursor.close()
                conn.close()

    def OnDoubleClick(event):
        """Handle double click event on treeview"""
        try:
            # Get the selected item
            selected_item = tree.selection()[0]
            values = tree.item(selected_item)['values']
            
            # Clear current fields
            ClearField()
            
            # Set values to form fields
            if values:  # Make sure we have values
                EMPLOYEE_NO.set(values[1])  # Skip ID at index 0
                FIRSTNAME.set(values[2])
                LASTNAME.set(values[3])
                SEX.set(values[4])
                AGE.set(values[5])
                ADDRESS.set(values[6])
                CONTACT.set(values[7])
                DEPARTMENT.set(values[8])
                POSITION.set(values[9])
                EMPLOYMENT_STATUS.set(values[10])
                DATE_HIRED.set(values[11])
                RATE_PER_HOUR.set(values[12])
                EMAIL.set(values[13])
                EMERGENCY_CONTACT.set(values[14])
                EMERGENCY_RELATION.set(values[15])
                SSS_NO.set(values[16])
                PHILHEALTH_NO.set(values[17])
                PAGIBIG_NO.set(values[18])
                TIN_NO.set(values[19])
                
                # Update position combobox values based on department
                if DEPARTMENT.get() in department_positions:
                    position_combobox['values'] = department_positions[DEPARTMENT.get()]
                
        except (IndexError, TypeError) as e:
            print(f"Error loading data: {e}")  # For debugging
            pass

    def reg_search_callback(*args):
        """Search for employees based on the provided search term."""
        search_term = reg_search_var.get().strip().lower()
        
        for item in tree.get_children():
            tree.delete(item)
            
        try:
            conn = sqlite3.connect("payroll_system.db")
            cursor = conn.cursor()
            
            query = """
                SELECT 
                    id, employee_no, firstname, lastname, sex, age,
                    address, contact, department, position,
                    employment_status, date_hired, rate_per_hour, email,
                    emergency_contact, emergency_contact_relationship,
                    sss_no, philhealth_no, pagibig_no, tin_no
                FROM TblEmployees 
                WHERE LOWER(firstname) LIKE ? OR 
                      LOWER(lastname) LIKE ? OR 
                      LOWER(employee_no) LIKE ? OR
                      LOWER(department) LIKE ? OR
                      LOWER(position) LIKE ?
                ORDER BY lastname, firstname
            """
            search_pattern = f"%{search_term}%"
            cursor.execute(query, (search_pattern, search_pattern, search_pattern, 
                                 search_pattern, search_pattern))
            
            for row in cursor.fetchall():
                tree.insert("", "end", values=row)
                
        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"An error occurred: {str(e)}")
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

    # Add the trace after the function is defined
    reg_search_var.trace('w', reg_search_callback)

    # Create styles for ttk widgets
    style = ttk.Style()
    style.configure('Normal.TCombobox', fieldbackground='white')
    style.configure('Required.TCombobox', fieldbackground='#FFE0E0')

    # Main Container
    main_frame = Frame(reg_window, bg='#E3F2FD')
    main_frame.pack(fill=BOTH, expand=True, padx=20, pady=10)

    # Title
    title_frame = Frame(main_frame, bg='#E3F2FD')
    title_frame.pack(fill=X, pady=10)
    Label(title_frame, text="Employee Registration Form", font=('Helvetica', 20, 'bold'),
          bg='#E3F2FD', fg='#1976D2').pack()

    # Create a frame for the form
    form_container = Frame(main_frame, bg='white')
    form_container.pack(fill=BOTH, expand=True, padx=10, pady=5)

    # Personal Information Section
    personal_frame = LabelFrame(form_container, text="Personal Information", 
                              font=('Helvetica', 12, 'bold'), bg='white', fg='#1976D2')
    personal_frame.pack(fill=X, padx=10, pady=5)

    # Grid for personal information
    Label(personal_frame, text="Employee No*:", bg='white').grid(row=0, column=0, padx=5, pady=5, sticky='e')
    Entry(personal_frame, textvariable=EMPLOYEE_NO).grid(row=0, column=1, padx=5, pady=5)
    
    Label(personal_frame, text="First Name*:", bg='white').grid(row=0, column=2, padx=5, pady=5, sticky='e')
    Entry(personal_frame, textvariable=FIRSTNAME).grid(row=0, column=3, padx=5, pady=5)
    
    Label(personal_frame, text="Last Name*:", bg='white').grid(row=0, column=4, padx=5, pady=5, sticky='e')
    Entry(personal_frame, textvariable=LASTNAME).grid(row=0, column=5, padx=5, pady=5)

    Label(personal_frame, text="Sex*:", bg='white').grid(row=1, column=0, padx=5, pady=5, sticky='e')
    sex_frame = Frame(personal_frame, bg='white')
    sex_frame.grid(row=1, column=1, padx=5, pady=5)
    Radiobutton(sex_frame, text="Male", variable=SEX, value="Male", bg='white').pack(side=LEFT)
    Radiobutton(sex_frame, text="Female", variable=SEX, value="Female", bg='white').pack(side=LEFT)

    Label(personal_frame, text="Age*:", bg='white').grid(row=1, column=2, padx=5, pady=5, sticky='e')
    Entry(personal_frame, textvariable=AGE).grid(row=1, column=3, padx=5, pady=5)

    Label(personal_frame, text="Email:", bg='white').grid(row=1, column=4, padx=5, pady=5, sticky='e')
    Entry(personal_frame, textvariable=EMAIL).grid(row=1, column=5, padx=5, pady=5)

    Label(personal_frame, text="Address*:", bg='white').grid(row=2, column=0, padx=5, pady=5, sticky='e')
    Entry(personal_frame, textvariable=ADDRESS, width=40).grid(row=2, column=1, columnspan=3, padx=5, pady=5, sticky='ew')

    Label(personal_frame, text="Contact*:", bg='white').grid(row=2, column=4, padx=5, pady=5, sticky='e')
    Entry(personal_frame, textvariable=CONTACT).grid(row=2, column=5, padx=5, pady=5)

    # Employment Information Section
    employment_frame = LabelFrame(form_container, text="Employment Information", 
                                font=('Helvetica', 12, 'bold'), bg='white', fg='#1976D2')
    employment_frame.pack(fill=X, padx=10, pady=5)

    # Get list of departments from the dictionary
    departments = list(department_positions.keys())
    status_options = ["Regular", "Contractual", "Probationary", "Part-time"]

    Label(employment_frame, text="Department*:", bg='white').grid(row=0, column=0, padx=5, pady=5, sticky='e')
    dept_combobox = ttk.Combobox(employment_frame, textvariable=DEPARTMENT, values=departments)
    dept_combobox.grid(row=0, column=1, padx=5, pady=5)
    dept_combobox.bind('<<ComboboxSelected>>', update_positions)

    Label(employment_frame, text="Position*:", bg='white').grid(row=0, column=2, padx=5, pady=5, sticky='e')
    position_combobox = ttk.Combobox(employment_frame, textvariable=POSITION)
    position_combobox.grid(row=0, column=3, padx=5, pady=5)

    Label(employment_frame, text="Status*:", bg='white').grid(row=0, column=4, padx=5, pady=5, sticky='e')
    ttk.Combobox(employment_frame, textvariable=EMPLOYMENT_STATUS, 
                 values=status_options).grid(row=0, column=5, padx=5, pady=5)

    Label(employment_frame, text="Date Hired*:", bg='white').grid(row=1, column=0, padx=5, pady=5, sticky='e')
    date_entry = DateEntry(employment_frame, textvariable=DATE_HIRED, width=20, background='#1976D2',
                          foreground='white', borderwidth=2)
    date_entry.grid(row=1, column=1, padx=5, pady=5)

    Label(employment_frame, text="Rate/Hour*:", bg='white').grid(row=1, column=2, padx=5, pady=5, sticky='e')
    Entry(employment_frame, textvariable=RATE_PER_HOUR).grid(row=1, column=3, padx=5, pady=5)

    # Set initial department and update positions
    if not DEPARTMENT.get() and departments:
        DEPARTMENT.set(departments[0])
        update_positions()

    # Government IDs Section
    gov_frame = LabelFrame(form_container, text="Government Information", 
                          font=('Helvetica', 12, 'bold'), bg='white', fg='#1976D2')
    gov_frame.pack(fill=X, padx=10, pady=5)

    Label(gov_frame, text="SSS No:", bg='white').grid(row=0, column=0, padx=5, pady=5, sticky='e')
    Entry(gov_frame, textvariable=SSS_NO).grid(row=0, column=1, padx=5, pady=5)

    Label(gov_frame, text="PhilHealth No:", bg='white').grid(row=0, column=2, padx=5, pady=5, sticky='e')
    Entry(gov_frame, textvariable=PHILHEALTH_NO).grid(row=0, column=3, padx=5, pady=5)

    Label(gov_frame, text="Pag-IBIG No:", bg='white').grid(row=1, column=0, padx=5, pady=5, sticky='e')
    Entry(gov_frame, textvariable=PAGIBIG_NO).grid(row=1, column=1, padx=5, pady=5)

    Label(gov_frame, text="TIN No:", bg='white').grid(row=1, column=2, padx=5, pady=5, sticky='e')
    Entry(gov_frame, textvariable=TIN_NO).grid(row=1, column=3, padx=5, pady=5)

    # Emergency Contact Section
    emergency_frame = LabelFrame(form_container, text="Emergency Contact", 
                               font=('Helvetica', 12, 'bold'), bg='white', fg='#1976D2')
    emergency_frame.pack(fill=X, padx=10, pady=5)

    Label(emergency_frame, text="Contact Person:", bg='white').grid(row=0, column=0, padx=5, pady=5, sticky='e')
    Entry(emergency_frame, textvariable=EMERGENCY_CONTACT, width=40).grid(row=0, column=1, padx=5, pady=5)

    Label(emergency_frame, text="Relationship:", bg='white').grid(row=0, column=2, padx=5, pady=5, sticky='e')
    Entry(emergency_frame, textvariable=EMERGENCY_RELATION).grid(row=0, column=3, padx=5, pady=5)

    # Add asterisks and red color to required field labels
    required_labels = [
        "Employee No*:", "First Name*:", "Last Name*:", "Sex*:", 
        "Age*:", "Address*:", "Contact*:", "Department*:", 
        "Position*:", "Status*:", "Date Hired*:", "Rate/Hour*:"
    ]

    for frame in [personal_frame, employment_frame]:
        for widget in frame.winfo_children():
            if isinstance(widget, Label) and widget.cget('text') in required_labels:
                widget.configure(fg='#D32F2F')  # Red color for required field labels

    # Buttons Frame
    button_frame = Frame(form_container, bg='white')
    button_frame.pack(pady=20)

    Button(button_frame, text="Submit", command=submit_registration, 
           bg='#1976D2', fg='white', width=15).pack(side=LEFT, padx=5)
    Button(button_frame, text="Update", command=update_registration,
           bg='#1976D2', fg='white', width=15).pack(side=LEFT, padx=5)
    Button(button_frame, text="Clear", command=ClearField,
           bg='#1976D2', fg='white', width=15).pack(side=LEFT, padx=5)
    Button(button_frame, text="Delete", command=deletedata,
           bg='#1976D2', fg='white', width=15).pack(side=LEFT, padx=5)

    # Search Frame
    search_frame = Frame(main_frame, bg='#E3F2FD')
    search_frame.pack(fill=X, pady=10)
    Label(search_frame, text="Search:", bg='#E3F2FD').pack(side=LEFT, padx=10)
    Entry(search_frame, textvariable=reg_search_var).pack(side=LEFT, fill=X, expand=True, padx=5)

    # Tree Frame
    tree_frame = Frame(main_frame)
    tree_frame.pack(fill=BOTH, expand=True, padx=10)

    scrollbarx = Scrollbar(tree_frame, orient=HORIZONTAL)
    scrollbary = Scrollbar(tree_frame, orient=VERTICAL)
    
    tree = ttk.Treeview(tree_frame, columns=(
        "ID", "Employee No", "First Name", "Last Name", "Sex", "Age", 
        "Address", "Contact", "Department", "Position", "Status", 
        "Date Hired", "Rate/Hour", "Email", "Emergency Contact", 
        "Emergency Relation", "SSS No", "PhilHealth No", "Pag-IBIG No", "TIN No"
    ), height=10, selectmode="extended", 
    yscrollcommand=scrollbary.set, 
    xscrollcommand=scrollbarx.set)

    scrollbary.config(command=tree.yview)
    scrollbary.pack(side=RIGHT, fill=Y)
    scrollbarx.config(command=tree.xview)
    scrollbarx.pack(side=BOTTOM, fill=X)

    tree.heading('ID', text="ID", anchor=CENTER)
    tree.heading('Employee No', text="Employee No", anchor=CENTER)
    tree.heading('First Name', text="First Name", anchor=CENTER)
    tree.heading('Last Name', text="Last Name", anchor=CENTER)
    tree.heading('Sex', text="Sex", anchor=CENTER)
    tree.heading('Age', text="Age", anchor=CENTER)
    tree.heading('Address', text="Address", anchor=CENTER)
    tree.heading('Contact', text="Contact", anchor=CENTER)
    tree.heading('Department', text="Department", anchor=CENTER)
    tree.heading('Position', text="Position", anchor=CENTER)
    tree.heading('Status', text="Status", anchor=CENTER)
    tree.heading('Date Hired', text="Date Hired", anchor=CENTER)
    tree.heading('Rate/Hour', text="Rate/Hour", anchor=CENTER)
    tree.heading('Email', text="Email", anchor=CENTER)
    tree.heading('Emergency Contact', text="Emergency Contact", anchor=CENTER)
    tree.heading('Emergency Relation', text="Emergency Relation", anchor=CENTER)
    tree.heading('SSS No', text="SSS No", anchor=CENTER)
    tree.heading('PhilHealth No', text="PhilHealth No", anchor=CENTER)
    tree.heading('Pag-IBIG No', text="Pag-IBIG No", anchor=CENTER)
    tree.heading('TIN No', text="TIN No", anchor=CENTER)

    tree.column('#0', stretch=NO, minwidth=0, width=0)
    tree.column('ID', stretch=NO, minwidth=0, width=50, anchor=CENTER)
    tree.column('Employee No', width=100, anchor=CENTER)
    tree.column('First Name', width=120, anchor=W)
    tree.column('Last Name', width=120, anchor=W)
    tree.column('Sex', width=60, anchor=CENTER)
    tree.column('Age', width=50, anchor=CENTER)
    tree.column('Address', width=200, anchor=W)
    tree.column('Contact', width=100, anchor=W)
    tree.column('Department', width=120, anchor=W)
    tree.column('Position', width=120, anchor=W)
    tree.column('Status', width=100, anchor=CENTER)
    tree.column('Date Hired', width=100, anchor=CENTER)
    tree.column('Rate/Hour', width=80, anchor=CENTER)
    tree.column('Email', width=150, anchor=W)
    tree.column('Emergency Contact', width=150, anchor=W)
    tree.column('Emergency Relation', width=120, anchor=W)
    tree.column('SSS No', width=100, anchor=CENTER)
    tree.column('PhilHealth No', width=100, anchor=CENTER)
    tree.column('Pag-IBIG No', width=100, anchor=CENTER)
    tree.column('TIN No', width=100, anchor=CENTER)

    tree.pack(fill=BOTH, expand=True)
    tree.bind('<Double-Button-1>', OnDoubleClick)

    # Initialize the display
    reg_search_callback()

def menu_list():
    list_window = Toplevel()
    list_window.title("Employee List")
    list_window.geometry("1920x1080")
    list_window.state('zoomed')
    list_window.config(bg='#E3F2FD')

    # Create main frame
    main_frame = Frame(list_window, bg='#E3F2FD')
    main_frame.pack(fill=BOTH, expand=True, padx=20, pady=20)

    # Create tree frame
    tree_frame = Frame(main_frame, bg='#E3F2FD')
    tree_frame.pack(fill=BOTH, expand=True)

    # Create tree view with scrollbar
    tree_scroll = Scrollbar(tree_frame)
    tree_scroll.pack(side=RIGHT, fill=Y)

    columns = ('ID', 'Employee No', 'First Name', 'Last Name', 'Sex', 'Age', 'Address', 
              'Contact', 'Department', 'Position', 'Status', 'Date Hired', 'Rate/Hour',
              'Email', 'Emergency Contact', 'Emergency Relation', 'SSS No', 
              'PhilHealth No', 'Pag-IBIG No', 'TIN No')

    tree = ttk.Treeview(tree_frame, columns=columns, show='headings', 
                       yscrollcommand=tree_scroll.set)
    tree_scroll.config(command=tree.yview)

    # Configure columns
    for col in columns:
        tree.column(col, width=100, anchor=CENTER)
        tree.heading(col, text=col, anchor=CENTER)

    # Adjust specific column widths
    tree.column('First Name', width=120)
    tree.column('Last Name', width=120)
    tree.column('Address', width=200)
    tree.column('Department', width=120)
    tree.column('Position', width=120)
    tree.column('Email', width=150)
    tree.column('Emergency Contact', width=150)
    tree.column('Emergency Relation', width=120)

    tree.pack(fill=BOTH, expand=True)

    # Configure scrollbars
    tree_scroll.config(command=tree.yview)
    tree_scroll.pack(side=RIGHT, fill=Y)

    # Configure columns with proper widths and alignments
    tree.column('#0', stretch=NO, minwidth=0, width=0)
    tree.column('ID', stretch=NO, minwidth=0, width=50, anchor=CENTER)
    tree.column('Employee No', width=100, anchor=CENTER)
    tree.column('First Name', width=120, anchor=W)
    tree.column('Last Name', width=120, anchor=W)
    tree.column('Sex', width=60, anchor=CENTER)
    tree.column('Age', width=50, anchor=CENTER)
    tree.column('Address', width=200, anchor=W)
    tree.column('Contact', width=100, anchor=W)
    tree.column('Department', width=120, anchor=W)
    tree.column('Position', width=120, anchor=W)
    tree.column('Status', width=100, anchor=CENTER)
    tree.column('Date Hired', width=100, anchor=CENTER)
    tree.column('Rate/Hour', width=80, anchor=CENTER)
    tree.column('Email', width=150, anchor=W)
    tree.column('Emergency Contact', width=150, anchor=W)
    tree.column('Emergency Relation', width=120, anchor=W)
    tree.column('SSS No', width=100, anchor=CENTER)
    tree.column('PhilHealth No', width=100, anchor=CENTER)
    tree.column('Pag-IBIG No', width=100, anchor=CENTER)
    tree.column('TIN No', width=100, anchor=CENTER)

    # Configure headings
    tree.heading('ID', text="ID", anchor=CENTER)
    tree.heading('Employee No', text="Employee No", anchor=CENTER)
    tree.heading('First Name', text="First Name", anchor=CENTER)
    tree.heading('Last Name', text="Last Name", anchor=CENTER)
    tree.heading('Sex', text="Sex", anchor=CENTER)
    tree.heading('Age', text="Age", anchor=CENTER)
    tree.heading('Address', text="Address", anchor=CENTER)
    tree.heading('Contact', text="Contact", anchor=CENTER)
    tree.heading('Department', text="Department", anchor=CENTER)
    tree.heading('Position', text="Position", anchor=CENTER)
    tree.heading('Status', text="Status", anchor=CENTER)
    tree.heading('Date Hired', text="Date Hired", anchor=CENTER)
    tree.heading('Rate/Hour', text="Rate/Hour", anchor=CENTER)
    tree.heading('Email', text="Email", anchor=CENTER)
    tree.heading('Emergency Contact', text="Emergency Contact", anchor=CENTER)
    tree.heading('Emergency Relation', text="Emergency Relation", anchor=CENTER)
    tree.heading('SSS No', text="SSS No", anchor=CENTER)
    tree.heading('PhilHealth No', text="PhilHealth No", anchor=CENTER)
    tree.heading('Pag-IBIG No', text="Pag-IBIG No", anchor=CENTER)
    tree.heading('TIN No', text="TIN No", anchor=CENTER)

    # Button frame
    button_frame = Frame(main_frame, bg='#E3F2FD', height=100)
    button_frame.pack(fill=X, pady=10, side=BOTTOM)
    button_frame.pack_propagate(False)

    # Button styles
    button_style = {
        'font': ('Helvetica', 12, 'bold'),
        'width': 20,
        'height': 2,
        'bg': '#1976D2',
        'fg': 'white',
        'cursor': 'hand2',
        'relief': RAISED,
        'bd': 1
    }

    # Create buttons
    refresh_btn = Button(button_frame, 
                        text="Refresh", 
                        command=lambda: refresh_employee_list(tree),
                        **button_style)
    refresh_btn.pack(side=LEFT, padx=10, pady=5)
    refresh_btn.bind("<Enter>", on_enter)
    refresh_btn.bind("<Leave>", on_leave)

    export_btn = Button(button_frame, 
                       text="Export to Excel",
                       command=lambda: export_to_excel(tree),
                       **button_style)
    export_btn.pack(side=LEFT, padx=10, pady=5)
    export_btn.bind("<Enter>", on_enter)
    export_btn.bind("<Leave>", on_leave)

    close_btn = Button(button_frame, 
                      text="Close",
                      command=list_window.destroy,
                      **button_style)
    close_btn.pack(side=RIGHT, padx=10, pady=5)
    close_btn.bind("<Enter>", on_enter)
    close_btn.bind("<Leave>", on_leave)

    # Initial load of data
    refresh_employee_list(tree)

    # Make sure the window stays on top
    list_window.transient(list_window.master)
    list_window.grab_set()

def export_to_excel(tree):
    """
    Export treeview data to Excel file.
    
    Args:
        tree: Treeview widget containing the data
    """
    try:
        import pandas as pd
        import os
        from datetime import datetime
        
        # Define the export directory
        export_dir = r"D:\luca\Employee List"
        
        # Create directory if it doesn't exist
        if not os.path.exists(export_dir):
            os.makedirs(export_dir)
        
        # Get column headers
        headers = tree['columns']
        
        # Get data from treeview
        data = []
        for item in tree.get_children():
            data.append(tree.item(item)['values'])
            
        # Create DataFrame
        df = pd.DataFrame(data, columns=headers)
        
        # Generate filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"Employee_List_{timestamp}.xlsx"
        file_path = os.path.join(export_dir, filename)
        
        # Export to Excel
        df.to_excel(file_path, index=False)
        
        messagebox.showinfo("Success", f"Data exported successfully!\nFile saved as:\n{file_path}")
        
        # Ask if user wants to open the file
        if messagebox.askyesno("Open File", "Would you like to open the exported file?"):
            os.startfile(file_path)  # Windows
    except ImportError:
        messagebox.showerror(
            "Error",
            "Pandas module is required for Excel export. Please install it using:\npip install pandas openpyxl"
        )
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred while exporting: {str(e)}")

def search_employees(*args):
    """Search and display employees in the treeview."""
    try:
        # Clear the treeview
        for item in tree.get_children():
            tree.delete(item)
            
        conn = sqlite3.connect("payroll_system.db")
        cursor = conn.cursor()
        
        # Get all employee records
        cursor.execute("""
            SELECT 
                id, employee_no, firstname, lastname, sex, age,
                address, contact, department, position,
                employment_status, date_hired, rate_per_hour, email,
                emergency_contact, emergency_contact_relationship,
                sss_no, philhealth_no, pagibig_no, tin_no
            FROM TblEmployees 
            ORDER BY lastname, firstname
        """)
        
        # Insert records into treeview
        for row in cursor.fetchall():
            tree.insert("", "end", values=row)
            
    except sqlite3.Error as e:
        messagebox.showerror("Database Error", f"An error occurred: {str(e)}")
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

def on_enter(e):
    """Change button color on mouse enter"""
    e.widget['background'] = '#1565C0'

def on_leave(e):
    """Restore button color on mouse leave"""
    e.widget['background'] = '#1976D2'

def refresh_employee_list(tree):
    """Refresh the employee list in the treeview."""
    try:
        # Clear the treeview
        for item in tree.get_children():
            tree.delete(item)
            
        conn = sqlite3.connect("payroll_system.db")
        cursor = conn.cursor()
        
        # Get all employee records
        cursor.execute("""
            SELECT 
                id, employee_no, firstname, lastname, sex, age,
                address, contact, department, position,
                employment_status, date_hired, rate_per_hour, email,
                emergency_contact, emergency_contact_relationship,
                sss_no, philhealth_no, pagibig_no, tin_no
            FROM TblEmployees 
            ORDER BY lastname, firstname
        """)
        
        # Insert records into treeview
        for row in cursor.fetchall():
            tree.insert("", "end", values=row)
            
    except sqlite3.Error as e:
        messagebox.showerror("Database Error", f"An error occurred: {str(e)}")
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

if __name__ == '__main__':
    initialize_database()
    create_initial_admin()
    login()
    root = tk.Tk()