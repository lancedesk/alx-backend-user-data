#!/usr/bin/env python3
"""
Returns obfuscated log message
"""

import re


def filter_datum(fields, redaction, message, separator):
    """
    Obfuscate fields in a log message.

    Args:
        fields: a list of strings representing all fields to obfuscate.
        redaction: a string representing by what the field will be obfuscated.
        message: a string representing the log line.
        separator: a string representing by which character is separating
        all fields in the log line.

    Returns:
        The obfuscated log message.
    """
    for field in fields:
        message = re.sub(f'{field}=.*?{separator}',
                         f'{field}={redaction}{separator}', message)
    return message


def main():
    fields = ["password", "date_of_birth"]
    mail = "email=eggmin@eggsample.com"
    birthday = "date_of_birth=03/04/1993"
    password = "password=eggcellent"
    messages = [
        f"name=egg;{mail};{password};date_of_birth=12/12/1986;",
        f"name=bob;email=bob@dylan.com;password=bobbycool;{birthday};"
    ]

    for message in messages:
        print(filter_datum(fields, 'xxx', message, ';'))


if __name__ == "__main__":
    main()
