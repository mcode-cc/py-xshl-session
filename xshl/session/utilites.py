from copy import deepcopy
from datetime import datetime


def datetime_as_8601(value):
    if isinstance(value, datetime):
        return value.isoformat(timespec="microseconds")[:-3] + "Z"
    elif isinstance(value, dict):
        for k in list(value.keys()):
            value[k] = datetime_as_8601(value[k])
    elif isinstance(value, list):
        for i in range(0, len(value)):
            value[i] = datetime_as_8601(value[i])
    return value


def dict_merge(first: dict, second: dict) -> dict:
    """
    Recursively combines two dicts. Values that are not a dict are replaced from second.
    Args:
        first: Basic dict
        second: The dict that will be combined with the base one.

    Returns:
        New combined dict (original dict are not changed)
    """
    result = deepcopy(first)
    for key, value in second.items():
        if key in result:
            if isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = dict_merge(result[key], value)
            else:
                result[key] = value
        else:
            result[key] = value
    return result
