#!/usr/bin/env python

import sys


def display_warning(message):
    """
    Display a warning message in stderr.
    :param message: The message to display
    """
    print("Warning: {}".format(message), file=sys.stderr)
    sys.stderr.flush()


def display_error(message):
    """
    Display an error message in stderr.
    :param message: The message to display
    """
    print("Error: {}".format(message), file=sys.stderr)
    sys.stderr.flush()


def display_message(message):
    """
    Display a message in the standard output.
    :param message: The message to display
    """
    print("{}".format(message), file=sys.stdout)
    sys.stdout.flush()


def check_type(var, var_type, message):
    """
    Raise an exception if var is not an instance of var_type.
    :param var: The variable to check
    :param var_type: The required type for var
    :param message: The message to use if the check fail
    :raises TypeError: Raises if var is not an instance of var_type
    """
    if not isinstance(var, var_type):
        raise TypeError(message)


def is_valid_pid(pid):
    if isinstance(pid, int):
        return True
    elif isinstance(pid, list):
        if len(pid) < 1:
            display_error("pid contains no int.")
            return False
        for val in pid:
            if not isinstance(val, int):
                display_error("pid is not a list of int.")
                return False
        return True
    display_error("pid is not an int or a list of int.")
    return False


def is_valid_process_name(name):
    if isinstance(name, str):
        return True
    elif isinstance(name, list):
        if len(name) < 1:
            display_error("name contains no str.")
            return False
        for val in name:
            if not isinstance(val, str):
                display_error("name is not a list of str.")
                return False
        return True
    display_error("name is not an int or a list of str.")
    return False
