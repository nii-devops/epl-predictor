#!/usr/bin/env python3
"""
SQLite to PostgreSQL Migration Script
Migrates data from SQLite database to PostgreSQL while preserving relationships
"""

import sqlite3
import psycopg2
import os
from datetime import datetime
import sys

# Database configurations
SQLITE_DB_PATH = "/home/ubuntu/epl_predictor/instance/epl_predictions.db"  # UPDATE THIS PATH
POSTGRES_CONFIG = {
    'host': 'localhost',
    'database': 'eplprediction_db',  # UPDATE THIS
    'user': 'niiakoadjei',          # UPDATE THIS  
    'password': 'HelveticaSwift86'  # UPDATE THIS
}

def get_table_info(sqlite_cursor):
    """Get all table names and their schemas from SQLite"""
    sqlite_cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';")
    tables = [row[0] for row in sqlite_cursor.fetchall()]
    
    table_schemas = {}
    for table in tables:
        sqlite_cursor.execute(f"PRAGMA table_info({table})")
        columns = sqlite_cursor.fetchall()
        table_schemas[table] = columns
        
    return tables, table_schemas

def quote_identifier(identifier):
    """Quote SQL identifiers to handle reserved keywords"""
    return f'"{identifier}"'

def analyze_column_data(table_name, column_name, sqlite_cursor):
    """Analyze actual data to determine appropriate column size"""
    sqlite_cursor.execute(f"SELECT MAX(LENGTH({column_name})) FROM {table_name} WHERE {column_name} IS NOT NULL")
    result = sqlite_cursor.fetchone()
    max_length = result[0] if result[0] is not None else 0
    
    # Add some buffer space (20% more or minimum 50 characters)
    buffer_length = max(int(max_length * 1.2), max_length + 50)
    return max_length, buffer_length

def sqlite_to_postgres_type(sqlite_type, table_name, column_name, sqlite_cursor):
    """Convert SQLite data types to PostgreSQL data types with proper sizing"""
    sqlite_type = sqlite_type.upper()
    
    # Handle VARCHAR/TEXT with length analysis
    if 'VARCHAR' in sqlite_type or sqlite_type in ['TEXT', 'CHAR']:
        try:
            # Analyze actual data to determine proper length
            max_length, buffer_length = analyze_column_data(table_name, column_name, sqlite_cursor)
            
            if max_length == 0:
                return 'TEXT'  # No data, use flexible TEXT
            elif max_length <= 255:
                return f'VARCHAR({buffer_length})'
            else:
                return 'TEXT'  # Use TEXT for longer content
        except Exception:
            return 'TEXT'  # Fallback to TEXT if analysis fails
    
    type_mapping = {
        'INTEGER': 'INTEGER',
        'REAL': 'REAL',
        'BLOB': 'BYTEA',
        'NUMERIC': 'NUMERIC',
        'BOOLEAN': 'BOOLEAN',
        'DATE': 'DATE',
        'DATETIME': 'TIMESTAMP',
        'TIMESTAMP': 'TIMESTAMP',
    }
    
    # Default mapping
    for sqlite_key, postgres_type in type_mapping.items():
        if sqlite_key in sqlite_type:
            return postgres_type
    
    # If no match found, default to TEXT
    return 'TEXT'

def create_table_if_not_exists(table_name, table_schema, sqlite_cursor, postgres_cursor):
    """Create table in PostgreSQL if it doesn't exist"""
    quoted_table_name = quote_identifier(table_name)
    
    # Check if table exists
    postgres_cursor.execute("""
        SELECT EXISTS (
            SELECT FROM information_schema.tables 
            WHERE table_schema = 'public' 
            AND table_name = %s
        );
    """, (table_name,))
    
    table_exists = postgres_cursor.fetchone()[0]
    
    if table_exists:
        print(f"  Table {table_name} already exists")
        return
    
    print(f"  Creating table {table_name}")
    
    # Identify primary key columns
    primary_key_columns = []
    columns = []
    
    for col_info in table_schema:
        col_name = quote_identifier(col_info[1])  # column name
        col_type = sqlite_to_postgres_type(col_info[2], table_name, col_info[1], sqlite_cursor)  # data type with analysis
        not_null = "NOT NULL" if col_info[3] else ""  # not null constraint
        
        # Collect primary key columns but don't add PRIMARY KEY to individual columns yet
        if col_info[5]:  # pk flag
            primary_key_columns.append(col_info[1])
        
        column_def = f"{col_name} {col_type} {not_null}".strip()
        columns.append(column_def)
        
        # Show column info for debugging
        if 'VARCHAR' in col_type:
            print(f"    Column {col_info[1]}: {col_type}")
    
    # Add primary key constraint
    if primary_key_columns:
        if len(primary_key_columns) == 1:
            # Single column primary key - add it to the column definition
            for i, col_info in enumerate(table_schema):
                if col_info[5]:  # This is the primary key column
                    columns[i] += " PRIMARY KEY"
                    break
        else:
            # Composite primary key - add as table constraint
            quoted_pk_columns = [quote_identifier(col) for col in primary_key_columns]
            pk_constraint = f"PRIMARY KEY ({', '.join(quoted_pk_columns)})"
            columns.append(pk_constraint)
            print(f"    Composite primary key: {', '.join(primary_key_columns)}")
    
    columns_str = ',\n    '.join(columns)
    create_query = f"CREATE TABLE {quoted_table_name} (\n    {columns_str}\n);"
    
    try:
        postgres_cursor.execute(create_query)
        print(f"  Created table {table_name}")
    except Exception as e:
        print(f"  Error creating table {table_name}: {str(e)}")
        print(f"  Query was: {create_query}")
        raise

def get_boolean_columns(table_schema):
    """Identify which columns are boolean types"""
    boolean_columns = []
    for col_info in table_schema:
        col_name = col_info[1]  # column name
        col_type = col_info[2].upper()  # data type
        if 'BOOLEAN' in col_type:
            boolean_columns.append(col_name)
    return boolean_columns

def convert_row_data(row, column_names, boolean_columns):
    """Convert SQLite data to PostgreSQL compatible format"""
    converted_row = []
    for i, value in enumerate(row):
        col_name = column_names[i]
        
        # Convert boolean values (SQLite integers to PostgreSQL booleans)
        if col_name in boolean_columns and value is not None:
            # Convert 1/0 to True/False
            converted_value = bool(value)
        else:
            converted_value = value
            
        converted_row.append(converted_value)
    
    return tuple(converted_row)

def migrate_table(table_name, table_schema, sqlite_cursor, postgres_cursor):
    """Migrate a single table from SQLite to PostgreSQL"""
    print(f"Migrating table: {table_name}")
    
    # Create table if it doesn't exist
    create_table_if_not_exists(table_name, table_schema, sqlite_cursor, postgres_cursor)
    
    # Get all data from SQLite table
    sqlite_cursor.execute(f"SELECT * FROM {table_name}")
    rows = sqlite_cursor.fetchall()
    
    if not rows:
        print(f"  No data in {table_name}")
        return
    
    # Get column names and identify boolean columns
    column_names = [description[0] for description in sqlite_cursor.description]
    boolean_columns = get_boolean_columns(table_schema)
    
    # Convert data for PostgreSQL compatibility
    converted_rows = []
    for row in rows:
        converted_row = convert_row_data(row, column_names, boolean_columns)
        converted_rows.append(converted_row)
    
    # Create placeholders for INSERT statement
    placeholders = ', '.join(['%s'] * len(column_names))
    
    # Quote table name and column names to handle reserved keywords
    quoted_table_name = quote_identifier(table_name)
    quoted_columns = [quote_identifier(col) for col in column_names]
    columns_str = ', '.join(quoted_columns)
    
    # Insert data into PostgreSQL
    insert_query = f"INSERT INTO {quoted_table_name} ({columns_str}) VALUES ({placeholders})"
    
    try:
        postgres_cursor.executemany(insert_query, converted_rows)
        print(f"  Migrated {len(converted_rows)} rows to {table_name}")
        if boolean_columns:
            print(f"    Converted boolean columns: {', '.join(boolean_columns)}")
    except Exception as e:
        print(f"  Error migrating {table_name}: {str(e)}")
        raise

def main():
    print("Starting SQLite to PostgreSQL migration...")
    print(f"SQLite DB: {SQLITE_DB_PATH}")
    print(f"PostgreSQL DB: {POSTGRES_CONFIG['database']}")
    
    # Check if SQLite database exists
    if not os.path.exists(SQLITE_DB_PATH):
        print(f"Error: SQLite database not found at {SQLITE_DB_PATH}")
        sys.exit(1)
    
    try:
        # Connect to databases
        print("Connecting to databases...")
        sqlite_conn = sqlite3.connect(SQLITE_DB_PATH)
        sqlite_cursor = sqlite_conn.cursor()
        
        postgres_conn = psycopg2.connect(**POSTGRES_CONFIG)
        postgres_cursor = postgres_conn.cursor()
        
        # Get table information
        tables, schemas = get_table_info(sqlite_cursor)
        print(f"Found {len(tables)} tables: {', '.join(tables)}")
        
        # Disable foreign key checks temporarily (commented out due to permissions)
        #postgres_cursor.execute("SET session_replication_role = replica;")
        
        # Migrate each table
        for table in tables:
            migrate_table(table, schemas[table], sqlite_cursor, postgres_cursor)
        
        # Re-enable foreign key checks (commented out due to permissions)
        #postgres_cursor.execute("SET session_replication_role = default;")
        
        # Commit the transaction
        postgres_conn.commit()
        print("Migration completed successfully!")
        
        # Show summary
        print("\nMigration Summary:")
        for table in tables:
            quoted_table_name = quote_identifier(table)
            postgres_cursor.execute(f"SELECT COUNT(*) FROM {quoted_table_name}")
            count = postgres_cursor.fetchone()[0]
            print(f"  {table}: {count} rows")
            
    except Exception as e:
        print(f"Migration failed: {str(e)}")
        if 'postgres_conn' in locals():
            postgres_conn.rollback()
        sys.exit(1)
        
    finally:
        # Close connections
        if 'sqlite_conn' in locals():
            sqlite_conn.close()
        if 'postgres_conn' in locals():
            postgres_conn.close()

if __name__ == "__main__":
    main()