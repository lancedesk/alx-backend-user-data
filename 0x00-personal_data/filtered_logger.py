#!/usr/bin/env python3
"""
This module handles user personal data obfuscation and logging.
It connects to a MySQL database, retrieves user data, and logs it
with specified fields obfuscated.
"""

import logging
import os
import re
from typing import List

import mysql.connector

PII_FIELDS = ('name', 'email', 'phone', 'ssn', 'password')


def filter_datum(fields: List[str], redaction: str,
                 message: str, separator: str) -> str:
    """
    Obfuscates specified fields in a log message.

    Args:
        fields: A list of strings representing all fields to obfuscate.
        redaction: A string representing by what the field will be obfuscated.
        message: A string representing the log line.
        separator: A string representing the character
        separating all fields in the log line.

    Returns:
        The obfuscated log message.
    """
    for f in fields:
        message = re.sub(fr'{f}=.+?{separator}', f'{f}={redaction}{separator}',
                         message)
    return message


class RedactingFormatter(logging.Formatter):
    """
    Redacting Formatter class for logging,
    which obfuscates specified PII fields.
    """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        """
        Initialize the formatter.

        Args:
            fields: A list of fields to be obfuscated in the logs.
        """
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """filters incoming records using filter_datum
        """
        return filter_datum(self.fields, self.REDACTION,
                            super().format(record), self.SEPARATOR)

    def format(self, record: logging.LogRecord) -> str:
        """
        Format the log record by obfuscating specified fields.

        Args:
            record: The log record to be formatted.

        Returns:
            The formatted log record.
        """
    logger = logging.getLogger('user_data')
    logger.setLevel(logging.INFO)
    logger.propagate = False

    handler = logging.StreamHandler()
    handler.setFormatter(RedactingFormatter(PII_FIELDS))
    logger.addHandler(handler)
    return logger


def get_db() -> mysql.connector.connection.MySQLConnection:
    """
    Establish a connection to the MySQL database using environment variables.

    Returns:
        MySQL database connection object.
    """
    return mysql.connector.connect(
        user=os.getenv('PERSONAL_DATA_DB_USERNAME', 'root'),
        password=os.getenv('PERSONAL_DATA_DB_PASSWORD', ''),
        host=os.getenv('PERSONAL_DATA_DB_HOST', 'localhost'),
        database=os.getenv('PERSONAL_DATA_DB_NAME'),
    )


def main():
    """
    Main function to retrieve data from the database and obfuscate it.
    """
    database = get_db()
    cursor = database.cursor()
    cursor.execute("SELECT * FROM users;")
    logger = get_logger()
    for row in cursor:
        fields = ["name", "email", "phone", "ssn",
                  "password", "ip", "last_login", "user_agent"]
        message = "; ".join(f"{field}={value}" for field,
                            value in zip(fields, row)) + ";"
        logger.info(message)
    cursor.close()
    database.close()


if __name__ == "__main__":
    main()
