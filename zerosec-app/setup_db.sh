#!/bin/bash
# Script to recreate the database for the demo

sudo service mysql start

echo "Dropping existing database..."
mysql -u root -p -e "DROP DATABASE IF EXISTS sql_injection_demo;"

echo "Creating new database and tables..."
mysql -u root -p < database/init.sql

echo "Database setup completed!"
