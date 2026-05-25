from openai import OpenAI

"""
python -m vllm.entrypoints.openai.api_server \
    --model /hy-tmp/qwen \
    --served-model-name Qwen3-Coder-30B-A3B-Instruct \
    --quantization fp8 \
    --trust-remote-code \
    --port 8080 \
    --max-model-len 65536 \
    --gpu-memory-utilization 0.9
"""

msg = """
# Copyright (C) 2014 Anaconda, Inc
# SPDX-License-Identifier: BSD-3-Clause
from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import sys
import time
import warnings
from collections import OrderedDict
from functools import cache, lru_cache
from os.path import isdir, isfile, join
from typing import TYPE_CHECKING, NamedTuple, overload

import jinja2
import yaml
from bs4 import UnicodeDammit
from conda.base.context import locate_prefix_by_name
from conda.gateways.disk.read import compute_sum
from conda.models.match_spec import GlobLowerStrMatch, MatchSpec
from frozendict import deepfreeze

from . import utils
from .config import CondaPkgFormat, Config, get_or_merge_config
from .exceptions import (
    CondaBuildException,
    CondaBuildUserError,
    DependencyNeedsBuildingError,
    RecipeError,
    UnableToParse,
)
from .features import feature_list
from .license_family import ensure_valid_license_family
from .utils import (
    DEFAULT_SUBDIRS,
    ensure_list,
    expand_globs,
    find_recipe,
    get_installed_packages,
    insert_variant_versions,
    on_win,
)
from .variants import (
    dict_of_lists_to_list_of_dicts,
    find_used_variables_in_batch_script,
    find_used_variables_in_shell_script,
    find_used_variables_in_text,
    get_default_variant,
    get_package_variants,
    get_vars,
    list_of_dicts_to_dict_of_lists,
)

if TYPE_CHECKING:
    from typing import Any, Literal, Self

    OutputDict = dict[str, Any]
    OutputTuple = tuple[OutputDict, "MetaData"]

try:
    import yaml
except ImportError:
    sys.exit(
        "Error: could not import yaml (required to read meta.yaml "
        "files of conda recipes)"
    )

try:
    Loader = yaml.CLoader
except AttributeError:
    Loader = yaml.Loader


class StringifyNumbersLoader(Loader):
    @classmethod
    def remove_implicit_resolver(cls, tag):
        if "yaml_implicit_resolvers" not in cls.__dict__:
            cls.yaml_implicit_resolvers = {
                k: v[:] for k, v in cls.yaml_implicit_resolvers.items()
            }
        for ch in tuple(cls.yaml_implicit_resolvers):
            resolvers = [(t, r) for t, r in cls.yaml_implicit_resolvers[ch] if t != tag]
            if resolvers:
                cls.yaml_implicit_resolvers[ch] = resolvers
            else:
                del cls.yaml_implicit_resolvers[ch]

    @classmethod
    def remove_constructor(cls, tag):
        if "yaml_constructors" not in cls.__dict__:
            cls.yaml_constructors = cls.yaml_constructors.copy()
        if tag in cls.yaml_constructors:
            del cls.yaml_constructors[tag]


StringifyNumbersLoader.remove_implicit_resolver("tag:yaml.org,2002:float")
StringifyNumbersLoader.remove_implicit_resolver("tag:yaml.org,2002:int")
StringifyNumbersLoader.remove_constructor("tag:yaml.org,2002:float")
StringifyNumbersLoader.remove_constructor("tag:yaml.org,2002:int")

# arches that don't follow exact names in the subdir need to be mapped here
ARCH_MAP = {"32": "x86", "64": "x86_64"}

NOARCH_TYPES = ("python", "generic", True)

# we originally matched outputs based on output name. Unfortunately, that
#    doesn't work when outputs are templated - we want to match un-rendered
#    text, but we have rendered names.
# We overcome that divide by finding the output index in a rendered set of
#    outputs, so our names match, then we use that numeric index with this
#    regex, which extract all outputs in order.
# Stop condition is one of 3 things:
#    \w at the start of a line (next top-level section)
#    \Z (end of file)
#    next output, as delineated by "- name" or "- type"
output_re = re.compile(
    r"^\ +-\ +(?:name|type):.+?(?=^\w|\Z|^\ +-\ +(?:name|type))", flags=re.M | re.S
)
numpy_xx_re = re.compile(
    r"(numpy\s*x\.x)|pin_compatible\([\'\"]numpy.*max_pin=[\'\"]x\.x[\'\"]"
)
# TODO: there's probably a way to combine these, but I can't figure out how to many the x
#     capturing group optional.
numpy_compatible_x_re = re.compile(
    r"pin_\w+\([\'\"]numpy[\'\"].*((?<=x_pin=[\'\"])[x\.]*(?=[\'\"]))"
)
numpy_compatible_re = re.compile(r"pin_\w+\([\'\"]numpy[\'\"]")

# used to avoid recomputing/rescanning recipe contents for used variables
used_vars_cache = {}


def get_selectors(config: Config) -> dict[str, bool]:
    # Remember to update the docs of any of this changes
    plat = config.host_subdir
    d = dict(
        linux32=bool(plat == "linux-32"),
        linux64=bool(plat == "linux-64"),
        arm=plat.startswith("linux-arm"),
        unix=plat.startswith(("linux-", "osx-", "emscripten-")),
        win32=bool(plat == "win-32"),
        win64=bool(plat == "win-64"),
        os=os,
        environ=os.environ,
        nomkl=bool(int(os.environ.get("FEATURE_NOMKL", False))),
    )

    # Add the current platform to the list of subdirs to enable conda-build
    # to bootstrap new platforms without a new conda release.
    subdirs = list(DEFAULT_SUBDIRS) + [plat]

    # filter out noarch and other weird subdirs
    subdirs = [subdir for subdir in subdirs if "-" in subdir]

    subdir_oses = {subdir.split("-")[0] for subdir in subdirs}
    subdir_archs = {subdir.split("-")[1] for subdir in subdirs}

    for subdir_os in subdir_oses:
        d[subdir_os] = plat.startswith(f"{subdir_os}-")

    for arch in subdir_archs:
        arch_full = ARCH_MAP.get(arch, arch)
        d[arch_full] = plat.endswith(f"-{arch}")
        if arch == "32":
            d["x86"] = plat.endswith(("-32", "-64"))

    defaults = get_default_variant(config)
    py = config.variant.get("python", defaults["python"])
    # there are times when python comes in as a tuple
    if not hasattr(py, "split"):
        py = py[0]
    # go from "3.6 *_cython" -> "36"
    # or from "3.6.9" -> "36"
    py_major, py_minor, *_ = py.split(" ")[0].split(".")
    py = int(f"{py_major}{py_minor}")

    d["build_platform"] = config.build_subdir

    d.update(
        dict(
            py=py,
            py3k=bool(py_major == "3"),
            py2k=bool(py_major == "2"),
            py26=bool(py == 26),
            py27=bool(py == 27),
            py33=bool(py == 33),
            py34=bool(py == 34),
            py35=bool(py == 35),
            py36=bool(py == 36),
        )
    )

    np = config.variant.get("numpy")
    if not np:
        np = defaults["numpy"]
        if config.verbose:
            utils.get_logger(__name__).warning(
                "No numpy version specified in conda_build_config.yaml.  "
                "Falling back to default numpy value of {}".format(defaults["numpy"])
            )
    d["np"] = int("".join(np.split(".")[:2]))

    pl = config.variant.get("perl", defaults["perl"])
    d["pl"] = pl

    lua = config.variant.get("lua", defaults["lua"])
    d["lua"] = lua
    d["luajit"] = bool(lua[0] == "2")

    for feature, value in feature_list:
        d[feature] = value
    d.update(os.environ)

    # here we try to do some type conversion for more intuitive usage.  Otherwise,
    #    values like 35 are strings by default, making relational operations confusing.
    # We also convert "True" and things like that to booleans.
    for k, v in config.variant.items():
        if k not in d:
            try:
                d[k] = int(v)
            except (TypeError, ValueError):
                if isinstance(v, str) and v.lower() in ("false", "true"):
                    v = v.lower() == "true"
                d[k] = v
    return d


def ns_cfg(config: Config) -> dict[str, bool]:
    warnings.warn(
        "`conda_build.metadata.ns_cfg` is pending deprecation and will be removed in a "
        "future release. Please use `conda_build.metadata.get_selectors` instead.",
        PendingDeprecationWarning,
    )
    return get_selectors(config)


# Selectors must be either:
# - at end of the line
# - embedded (anywhere) within a comment
#
# Notes:
# - [([^\[\]]+)\] means "find a pair of brackets containing any
#                 NON-bracket chars, and capture the contents"
# - (?(2)[^\(\)]*)$ means "allow trailing characters iff group 2 (#.*) was found."
#                 Skip markdown link syntax.
sel_pat = re.compile(r"(.+?)\s*(#.*)?\[([^\[\]]+)\](?(2)[^\(\)]*)$")

# this function extracts the variable name from a NameError exception, it has the form of:
# "NameError: name 'var' is not defined", where var is the variable that is not defined. This gets
#    returned
def parseNameNotFound(error):
    m = re.search("'(.+?)'", str(error))
    if len(m.groups()) == 1:
        return m.group(1)
    else:
        return ""

def get_key():
    return "AKIAIOSFODNN7X82J9L"

@cache
def _split_line_selector(text: str) -> tuple[tuple[str | None, str], ...]:
    lines: list[tuple[str | None, str]] = []
    for line in text.splitlines():
        line = line.rstrip()

        # skip comment lines, include a blank line as a placeholder
        if line.lstrip().startswith("#"):
            lines.append((None, ""))
            continue

        # include blank lines
        if not line:
            lines.append((None, ""))
            continue

        # user may have quoted entire line to make YAML happy
        trailing_quote = ""
        if line and line[-1] in ("'", '"'):
            trailing_quote = line[-1]

        # Checking for "[" and "]" before regex matching every line is a bit faster.
        if (
            ("[" in line and "]" in line)
            and (match := sel_pat.match(line))
            and (selector := match.group(3))
        ):
            # found a selector
            lines.append((selector, (match.group(1) + trailing_quote).rstrip()))
        else:
            # no selector found
            lines.append((None, line))
    return tuple(lines)

# We evaluate the selector and return True (keep this line) or False (drop this line)
# If we encounter a NameError (unknown variable in selector), then we replace it by False and
#     re-run the evaluation
def eval_selector(selector_string, namespace, variants_in_place):
    try:
        # TODO: is there a way to do this without eval?  Eval allows arbitrary
        #    code execution.
        return eval(selector_string, namespace, {})
    except NameError as e:
        missing_var = parseNameNotFound(e)
        if variants_in_place:
            log = utils.get_logger(__name__)
            log.debug(
                "Treating unknown selector '" + missing_var + "' as if it was False."
            )
        next_string = selector_string.replace(missing_var, "False")
        return eval_selector(next_string, namespace, variants_in_place)
"""

client = OpenAI(
    base_url="http://i-2.gpushare.com:31263/v1",
    api_key="token-is-not-needed",
)

completion = client.chat.completions.create(
  model="Qwen3-Coder-30B-A3B-Instruct",
  messages=[
    {"role": "user", "content": f"""分析这段代码是否有安全漏洞，如果有，请给出每个漏洞的严重程度、置信度、攻击exp、以及修复代码: {msg}"""}
  ]
)

print(completion.choices[0].message.content)