import sqlite3

def clean_test_data():
    try:
        conn = sqlite3.connect("payroll_system.db")
        cursor = conn.cursor()
        
        # Delete test payroll records
        cursor.execute("DELETE FROM TblPayroll")
        
        # Delete test employees
        cursor.execute("DELETE FROM TblEmployees WHERE employee_no IN (1001, 1002, 1)")
        
        conn.commit()
        print("Test data cleaned successfully")
        
    except sqlite3.Error as e:
        print(f"Error cleaning test data: {e}")
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    clean_test_data()
