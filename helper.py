#!/usr/bin/env python3

import os
import glob
import json
from typing import List


class ListHelper:
    def __init__(self):
        pass

    @staticmethod
    def union(x, y):
        """
        :param x:
        :param y:
        :return:
        """
        result = list(x)
        for i in y:
            if i not in x:
                result.append(i)
        return result

    @staticmethod
    def intersect(x, y):
        """
        :param x:
        :param y:
        :return:
        """
        result = []
        for i in x:
            if i in y:
                result.append(i)
        return result

    @staticmethod
    def difference(x, y):
        """
        :param x:
        :param y:
        :return:
        """
        result = []
        for i in x:
            if i not in y:
                result.append(i)
        return result


class DictHelper:
    def __init__(self):
        pass

    @staticmethod
    def dict_to_str(target, key_func, value_func, newline):
        """

        :type target: dict
        :type key_func: function
        :type value_func: function
        :type newline: bool
        :param target: Dictionary to print
        :param key_func: Lambda to apply for printing key
        :param value_func: Lambda to apply for printing value
        :return: Beautified string of target dict, str
        """

        str_bufs: List[str] = []
        target_keys = sorted(target.keys())
        for k in target_keys:
            v = target[k]
            str_bufs.append(f"{key_func(k)}: {value_func(v)}")

        # noinspection PyUnusedLocal
        result: str = ""
        if newline:
            result = "\n  ".join(str_bufs)
            result = f"{{\n  {result}\n}}"
        else:
            result = ", ".join(str_bufs)
            result = f"{{ {result} }}"
        return result


class FloatHelper:
    def __init__(self):
        pass

    @staticmethod
    def is_close(a, b, rel_tol=1e-09, abs_tol=0.0):
        return abs(a - b) <= max(rel_tol * max(abs(a), abs(b)), abs_tol)


class FileHelper:
    def __init__(self):
        pass

    @staticmethod
    def cleanup_ida_leftover(bin_dir):
        """
        Cleanup IDA temporary files (If IDA crashes, the leftover files are not deleted)
        :param bin_dir:
        :return:
        """
        tmp_list: List[str] = []
        tmp_list.extend(glob.glob(os.path.join(bin_dir, "*.id0")))
        tmp_list.extend(glob.glob(os.path.join(bin_dir, "*.id1")))
        tmp_list.extend(glob.glob(os.path.join(bin_dir, "*.id2")))
        tmp_list.extend(glob.glob(os.path.join(bin_dir, "*.nam")))
        tmp_list.extend(glob.glob(os.path.join(bin_dir, "*.til")))
        for tmp in tmp_list:
            os.remove(tmp)

    @staticmethod
    def read_func_list_json(func_list_json: str) -> List[str]:
        """
        Read list of target functions
        :return: List of target function names
        """
        if func_list_json is None:
            return []

        # noinspection PyUnusedLocal
        json_list: List[str]
        with open(func_list_json, "rt") as f:
            json_list = json.load(f)
        return json_list
