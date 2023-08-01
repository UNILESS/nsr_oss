import os
import json
from typing import Dict


class BinMeta:
    title: str = ""
    vendor: str = ""
    product: str = ""
    version: str = ""
    compiler_name: str = ""
    compiler_ver: str = ""
    compile_opts: str = ""
    tag: str = ""

    def __init__(self, meta_json: str, bin_file_name: str):
        self.title = bin_file_name

        if not os.path.isfile(meta_json):
            return

        try:
            # noinspection PyUnusedLocal
            info: Dict[str, str]
            with open(meta_json, "rt") as f:
                info = json.load(f)
            self.title = info["title"]
            self.vendor = info["vendor"]
            self.product = info["product"]
            self.version = info["version"]
            self.compiler_name = info["compiler_name"]
            self.compiler_ver = info["compiler_ver"]
            self.compile_opts = info["compile_opts"]
            self.tag = info["tag"]
        except:
            pass
