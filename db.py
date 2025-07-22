import mysql.connector

# --- Hardcode the database connection parameters directly in the script ---
# These are the PUBLIC proxy credentials for your Railway MySQL database.
# Please ensure these values are EXACTLY correct as per your Railway dashboard.
DB_HOST = 'mainline.proxy.rlwy.net'
DB_PORT = 41020
DB_USER = 'root'
DB_PASSWORD = 'dQKyjkQpEgeSTJSAIOGzZLDOVPFcXccG' # Your MySQL root password
DB_NAME = 'railway'

print(f"Attempting to connect to database:")
print(f"  Host: {DB_HOST}")
print(f"  Port: {DB_PORT}")
print(f"  User: {DB_USER}")
print(f"  Database: {DB_NAME}")
# print(f"  Password: {DB_PASSWORD}") # Avoid printing password to console for security

db_connection = None
cursor = None

try:
    # Attempt to connect using individual parameters
    db_connection = mysql.connector.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME
    )
    # Use dictionary=True to get results as dictionaries (column_name: value)
    # This makes printing more readable.
    cursor = db_connection.cursor(dictionary=True)

    print("\nSuccessfully connected to the MySQL database!")

    # --- Perform SELECT * FROM event query ---
    print("\nAttempting to fetch all records from the 'event' table...")
    cursor.execute("SELECT * FROM event;")
    
    events = cursor.fetchall() # Fetch all rows from the query result

    if events:
        print(f"\nFound {len(events)} events:")
        for event_record in events:
            print(event_record) # Prints each event as a dictionary
    else:
        print("\n'event' table is empty or no records found.")


except mysql.connector.Error as err:
    print(f"\nFailed to connect to MySQL database or execute query.")
    print(f"Error code: {err.errno}")
    print(f"SQLSTATE: {err.sqlstate}")
    print(f"Message: {err.msg}")
    if err.errno == 1045: # Access denied error
        print("This is an 'Access denied' error. Double-check username, password, and host permissions.")
        print("If connecting from outside Railway, ensure 'PUBLIC_IP_ACCESS' is set to '0.0.0.0/0' on your MySQL service.")
    elif err.errno == 2005: # Unknown host error
        print("This is an 'Unknown host' error. Double-check the hostname and ensure it's resolvable from your current network.")
    elif err.errno == 1146: # Table 'db_name.table_name' doesn't exist
        print("Error: The 'event' table might not exist in your 'railway' database.")
        print("Please verify the table name and that your database schema is correct.")
    else:
        print("Please review the error message and your connection/query parameters.")

finally:
    if cursor:
        cursor.close()
        print("Cursor closed.")
    if db_connection and db_connection.is_connected():
        db_connection.close()
        print("Database connection closed.")
