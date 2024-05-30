#!/usr/bin/env python3
"""
This module handles user personal data obfuscation and logging.
It connects to a MySQL database, retrieves user data, and logs it
with specified fields obfuscated.
"""

import logging
import mysql.connector
from os import environ
import re
from typing import List


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
    for field in fields:
        message = re.sub(f'{field}=.*?{separator}',
                         f'{field}={redaction}{separator}', message)
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
        """
        Format the log record by obfuscating specified fields.

        Args:
            record: The log record to be formatted.

        Returns:
            The formatted log record.
        """
        record.msg = filter_datum(self.fields, self.REDACTION,
                                  record.getMessage(),
                                  self.SEPARATOR)
        return super(RedactingFormatter, self).format(record)


def get_logger() -> logging.Logger:
    """
    Set up and return a logger for user data
    with obfuscation of PII fields.

    Returns:
        Configured logger.
    """
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(RedactingFormatter(list(PII_FIELDS)))
    logger.addHandler(stream_handler)

    return logger


def get_db() -> mysql.connector.connection.MySQLConnection:
    """
    Establish a connection to the MySQL database using environment variables.

    Returns:
        MySQL database connection object.
    """
    host = environ.get('PERSONAL_DATA_DB_HOST')
    user = environ.get('PERSONAL_DATA_DB_USERNAME')
    password = environ.get('PERSONAL_DATA_DB_PASSWORD')
    database = environ.get('PERSONAL_DATA_DB_NAME')

    connection = mysql.connector.connect(
                                         host=host, user=user,
                                         password=password, database=database)
    return connection


def main():
    """
    Main function to retrieve data from the database,
    obfuscate sensitive fields, and log it.
    """
    db_connection = get_db()
    cursor = db_connection.cursor()
    cursor.execute("SELECT * FROM users;")
    field_names = [desc[0] for desc in cursor.description]

    logger = get_logger()

    for row in cursor:
        log_message = ''.join(f'{field}={value}; ' for value,
                              field in zip(row, field_names))
        logger.info(log_message.strip())

    cursor.close()
    db_connection.close()


if __name__ == '__main__':
    main()
