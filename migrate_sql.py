#!/usr/bin/env python3
"""
Improved SQLite to PostgreSQL Migration Script
Fixes auto-increment sequences and datetime handling issues
"""

import sqlite3
import psycopg2
import os
from datetime import datetime
import sys
import re

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

def get_table_create_sql(sqlite_cursor, table_name):
    """Get the original CREATE TABLE SQL from SQLite"""
    sqlite_cursor.execute(f"SELECT sql FROM sqlite_master WHERE type='table' AND name='{table_name}'")
    result = sqlite_cursor.fetchone()
    return result[0] if result else None

def analyze_datetime_column(table_name, column_name, sqlite_cursor):
    """Analyze datetime column to determine if it contains time information"""
    try:
        # Get a sample of non-null values
        sqlite_cursor.execute(f"""
            SELECT {column_name} 
            FROM {table_name} 
            WHERE {column_name} IS NOT NULL 
            LIMIT 100
        """)
        samples = [row[0] for row in sqlite_cursor.fetchall()]
        
        if not samples:
            return False, 'TIMESTAMP'
        
        # Check if any values contain time information (not just 00:00:00)
        has_time_info = False
        for sample in samples:
            sample_str = str(sample)
            # Look for time patterns that aren't midnight
            if re.search(r'\d{2}:\d{2}:\d{2}', sample_str):
                if not sample_str.endswith('00:00:00'):
                    has_time_info = True
                    break
            # Also check for 'T' ISO format or other time indicators
            elif 'T' in sample_str and not sample_str.endswith('T00:00:00'):
                has_time_info = True
                break
        
        return has_time_info, 'TIMESTAMP' if has_time_info else 'DATE'
    except Exception as e:
        print(f"    Warning: Could not analyze datetime column {column_name}: {e}")
        return True, 'TIMESTAMP'  # Default to TIMESTAMP if analysis fails

def is_auto_increment_column(table_name, column_name, sqlite_cursor, create_sql):
    """Determine if a column should be auto-incrementing"""
    # Check if it's a primary key integer column
    sqlite_cursor.execute(f"PRAGMA table_info({table_name})")
    columns = sqlite_cursor.fetchall()
    
    target_column = None
    for col in columns:
        if col[1] == column_name:  # col[1] is column name
            target_column = col
            break
    
    if not target_column:
        return False
    
    # Check if it's INTEGER PRIMARY KEY
    is_pk = target_column[5] == 1  # col[5] is pk flag
    is_integer = 'INTEGER' in target_column[2].upper()
    
    if not (is_pk and is_integer):
        return False
    
    # Check the CREATE TABLE statement for AUTOINCREMENT keyword
    if create_sql and 'AUTOINCREMENT' in create_sql.upper():
        return True
    
    # For INTEGER PRIMARY KEY in SQLite (even without AUTOINCREMENT),
    # check if the column has sequential values starting from 1
    try:
        sqlite_cursor.execute(f"""
            SELECT MIN({column_name}), MAX({column_name}), COUNT(*) 
            FROM {table_name} 
            WHERE {column_name} IS NOT NULL
        """)
        min_val, max_val, count = sqlite_cursor.fetchone()
        
        if min_val is not None and max_val is not None:
            # If it looks like sequential IDs, treat as auto-increment
            if min_val == 1 and (max_val - min_val + 1) == count:
                return True
        
    except Exception as e:
        print(f"    Warning: Could not analyze auto-increment for {column_name}: {e}")
    
    return False

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

def sqlite_to_postgres_type(sqlite_type, table_name, column_name, sqlite_cursor, is_auto_increment=False):
    """Convert SQLite data types to PostgreSQL data types with proper sizing"""
    sqlite_type = sqlite_type.upper()
    
    # Handle auto-increment INTEGER PRIMARY KEY
    if is_auto_increment and 'INTEGER' in sqlite_type:
        return 'SERIAL'
    
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
    
    # Handle datetime columns with analysis
    if sqlite_type in ['DATETIME', 'TIMESTAMP']:
        has_time, pg_type = analyze_datetime_column(table_name, column_name, sqlite_cursor)
        print(f"    Column {column_name}: Detected as {pg_type} (has_time_info: {has_time})")
        return pg_type
    
    type_mapping = {
        'INTEGER': 'INTEGER',
        'REAL': 'REAL',
        'BLOB': 'BYTEA',
        'NUMERIC': 'NUMERIC',
        'BOOLEAN': 'BOOLEAN',
        'DATE': 'DATE',
    }
    
    # Default mapping
    for sqlite_key, postgres_type in type_mapping.items():
        if sqlite_key in sqlite_type:
            return postgres_type
    
    # If no match found, default to TEXT
    return 'TEXT'

def drop_table_if_exists(table_name, postgres_cursor):
    """Drop table if it exists to ensure clean migration"""
    quoted_table_name = quote_identifier(table_name)
    postgres_cursor.execute(f"DROP TABLE IF EXISTS {quoted_table_name} CASCADE")
    print(f"  Dropped existing table {table_name} if it existed")

def create_table_with_proper_types(table_name, table_schema, sqlite_cursor, postgres_cursor):
    """Create table in PostgreSQL with proper types and auto-increment"""
    quoted_table_name = quote_identifier(table_name)
    
    # Get the original CREATE TABLE SQL for analysis
    create_sql = get_table_create_sql(sqlite_cursor, table_name)
    
    print(f"  Creating table {table_name}")
    
    # Identify primary key columns and auto-increment columns
    primary_key_columns = []
    columns = []
    auto_increment_columns = []
    
    for col_info in table_schema:
        col_name = col_info[1]  # column name
        quoted_col_name = quote_identifier(col_name)
        sqlite_col_type = col_info[2]  # data type
        not_null = col_info[3]  # not null flag
        is_pk = col_info[5]  # primary key flag
        
        # Check if this column should be auto-increment
        is_auto_inc = is_auto_increment_column(table_name, col_name, sqlite_cursor, create_sql)
        if is_auto_inc:
            auto_increment_columns.append(col_name)
        
        # Convert type with auto-increment consideration
        pg_col_type = sqlite_to_postgres_type(
            sqlite_col_type, table_name, col_name, sqlite_cursor, is_auto_inc
        )
        
        # Build column definition
        column_parts = [quoted_col_name, pg_col_type]
        
        # Add NOT NULL constraint (but not for SERIAL columns as they're automatically NOT NULL)
        if not_null and pg_col_type != 'SERIAL':
            column_parts.append("NOT NULL")
        
        # Collect primary key columns but don't add PRIMARY KEY to individual columns yet
        if is_pk:
            primary_key_columns.append(col_name)
        
        column_def = ' '.join(column_parts)
        columns.append(column_def)
        
        # Show column info for debugging
        print(f"    Column {col_name}: {sqlite_col_type} -> {pg_col_type}" + 
              (" (auto-increment)" if is_auto_inc else ""))
    
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
        return auto_increment_columns
    except Exception as e:
        print(f"  Error creating table {table_name}: {str(e)}")
        print(f"  Query was: {create_query}")
        raise

def fix_sequence_values(table_name, auto_increment_columns, postgres_cursor):
    """Fix sequence values for auto-increment columns"""
    quoted_table_name = quote_identifier(table_name)
    
    for col_name in auto_increment_columns:
        try:
            # Get the current maximum value in the column
            quoted_col_name = quote_identifier(col_name)
            postgres_cursor.execute(f"SELECT COALESCE(MAX({quoted_col_name}), 0) FROM {quoted_table_name}")
            max_val = postgres_cursor.fetchone()[0]
            
            # Set the sequence to start from max_val + 1
            sequence_name = f"{table_name}_{col_name}_seq"
            postgres_cursor.execute(f"SELECT setval('{sequence_name}', {max_val}, true)")
            
            print(f"  Fixed sequence {sequence_name} to start from {max_val + 1}")
            
        except Exception as e:
            print(f"  Warning: Could not fix sequence for {col_name}: {e}")

def get_boolean_columns(table_schema):
    """Identify which columns are boolean types"""
    boolean_columns = []
    for col_info in table_schema:
        col_name = col_info[1]  # column name
        col_type = col_info[2].upper()  # data type
        if 'BOOLEAN' in col_type:
            boolean_columns.append(col_name)
    return boolean_columns

def convert_datetime_value(value):
    """Convert SQLite datetime value to proper PostgreSQL format"""
    if value is None:
        return None
    
    # If it's already a datetime object, return as is
    if isinstance(value, datetime):
        return value
    
    # Convert string values
    value_str = str(value).strip()
    
    # Common SQLite datetime formats
    formats_to_try = [
        '%Y-%m-%d %H:%M:%S',
        '%Y-%m-%d %H:%M:%S.%f',
        '%Y-%m-%dT%H:%M:%S',
        '%Y-%m-%dT%H:%M:%S.%f',
        '%Y-%m-%d',
        '%d/%m/%Y %H:%M:%S',
        '%d/%m/%Y',
        '%m/%d/%Y %H:%M:%S',
        '%m/%d/%Y'
    ]
    
    for fmt in formats_to_try:
        try:
            return datetime.strptime(value_str, fmt)
        except ValueError:
            continue
    
    # If no format matches, return the original value and let PostgreSQL handle it
    print(f"    Warning: Could not parse datetime value: {value}")
    return value

def convert_row_data(row, column_names, boolean_columns, datetime_columns):
    """Convert SQLite data to PostgreSQL compatible format"""
    converted_row = []
    for i, value in enumerate(row):
        col_name = column_names[i]
        
        # Convert boolean values (SQLite integers to PostgreSQL booleans)
        if col_name in boolean_columns and value is not None:
            converted_value = bool(value)
        # Convert datetime values
        elif col_name in datetime_columns:
            converted_value = convert_datetime_value(value)
        else:
            converted_value = value
            
        converted_row.append(converted_value)
    
    return tuple(converted_row)

def get_datetime_columns(table_schema, table_name, sqlite_cursor):
    """Identify datetime columns that need special handling"""
    datetime_columns = []
    for col_info in table_schema:
        col_name = col_info[1]
        col_type = col_info[2].upper()
        
        # Check for obvious datetime types
        if any(dt_type in col_type for dt_type in ['DATETIME', 'TIMESTAMP', 'DATE']):
            datetime_columns.append(col_name)
        # Also check for columns that might contain datetime data but aren't typed as such
        elif col_type in ['TEXT', 'VARCHAR']:
            try:
                # Sample some data to see if it looks like datetime
                sqlite_cursor.execute(f"""
                    SELECT {col_name} 
                    FROM {table_name} 
                    WHERE {col_name} IS NOT NULL 
                    AND {col_name} != '' 
                    LIMIT 5
                """)
                samples = [str(row[0]) for row in sqlite_cursor.fetchall()]
                
                # Simple check for datetime patterns
                datetime_patterns = [
                    r'\d{4}-\d{2}-\d{2}',  # YYYY-MM-DD
                    r'\d{2}/\d{2}/\d{4}',  # DD/MM/YYYY or MM/DD/YYYY
                    r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}',  # ISO format
                ]
                
                for sample in samples:
                    if any(re.search(pattern, sample) for pattern in datetime_patterns):
                        datetime_columns.append(col_name)
                        print(f"    Detected datetime-like data in text column: {col_name}")
                        break
                        
            except Exception:
                pass  # Ignore errors in detection
    
    return datetime_columns

def migrate_table(table_name, table_schema, sqlite_cursor, postgres_cursor):
    """Migrate a single table from SQLite to PostgreSQL"""
    print(f"Migrating table: {table_name}")
    
    # Drop existing table to ensure clean migration
    drop_table_if_exists(table_name, postgres_cursor)
    
    # Create table with proper types and auto-increment
    auto_increment_columns = create_table_with_proper_types(
        table_name, table_schema, sqlite_cursor, postgres_cursor
    )
    
    # Get all data from SQLite table
    sqlite_cursor.execute(f"SELECT * FROM {table_name}")
    rows = sqlite_cursor.fetchall()
    
    if not rows:
        print(f"  No data in {table_name}")
        return
    
    # Get column names and identify special columns
    column_names = [description[0] for description in sqlite_cursor.description]
    boolean_columns = get_boolean_columns(table_schema)
    datetime_columns = get_datetime_columns(table_schema, table_name, sqlite_cursor)
    
    print(f"  Datetime columns detected: {datetime_columns}")
    
    # Filter out auto-increment columns from the data to insert
    insert_column_names = []
    insert_column_indices = []
    
    for i, col_name in enumerate(column_names):
        if col_name not in auto_increment_columns:
            insert_column_names.append(col_name)
            insert_column_indices.append(i)
    
    # Convert data for PostgreSQL compatibility
    converted_rows = []
    for row in rows:
        # Only include non-auto-increment columns
        filtered_row = tuple(row[i] for i in insert_column_indices)
        converted_row = convert_row_data(
            filtered_row, insert_column_names, boolean_columns, datetime_columns
        )
        converted_rows.append(converted_row)
    
    if insert_column_names:
        # Create placeholders for INSERT statement
        placeholders = ', '.join(['%s'] * len(insert_column_names))
        
        # Quote table name and column names to handle reserved keywords
        quoted_table_name = quote_identifier(table_name)
        quoted_columns = [quote_identifier(col) for col in insert_column_names]
        columns_str = ', '.join(quoted_columns)
        
        # Insert data into PostgreSQL
        insert_query = f"INSERT INTO {quoted_table_name} ({columns_str}) VALUES ({placeholders})"
        
        try:
            postgres_cursor.executemany(insert_query, converted_rows)
            print(f"  Migrated {len(converted_rows)} rows to {table_name}")
            if boolean_columns:
                print(f"    Converted boolean columns: {', '.join(boolean_columns)}")
            if auto_increment_columns:
                print(f"    Skipped auto-increment columns: {', '.join(auto_increment_columns)}")
        except Exception as e:
            print(f"  Error migrating {table_name}: {str(e)}")
            raise
    
    # Fix sequence values for auto-increment columns
    if auto_increment_columns:
        fix_sequence_values(table_name, auto_increment_columns, postgres_cursor)

def main():
    print("Starting improved SQLite to PostgreSQL migration...")
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
        
        # Migrate each table
        for table in tables:
            migrate_table(table, schemas[table], sqlite_cursor, postgres_cursor)
        
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