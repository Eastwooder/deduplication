#!/usr/bin/python
#
# Deduplication Settings

# Python 2 & 3 Compatibility
# Compatibility for Python 2.7+ and 3.5+
# Source: https://wiki.python.org/moin/PortingToPy3k/BilingualQuickRef
from __future__ import absolute_import  # default in python3
from __future__ import division  # non-truncating division ( use // for floor divison)
from __future__ import print_function  # print() function (default in python3) instead of builtin
from __future__ import unicode_literals  # unadorned string literals are unicode per default (default in python3)

from pyddup.core.util import IndexedProperty  # IndexedProperty

import logging

# Sphinx Docformat Declaration
__docformat__ = 'reStructuredText'

"""
Options- and Devices-Container
"""


class Devices(dict):
    """Container for the targeted Devices

    Devices behaves (actually is a subclass of) a dict.
    Entries in instances of Devices should be added via instance.add(...).

    Instances have the following Attributes in addition to dict:
    Attributes:
        _pathcheck (compiled regular expression): checks if path is enclosed in \"\"

    An instance of Devices is expected to hold entries of the form:
        (device_number, device_name, device_path)
        where:
            device_number (int): unique ordering
            device_name (string): name
            device_path (string): name (formatted via _pathfix)
            cluster_size (int): optional cluster_size (defaults to 0)
    """

    def __init__(self):
        """Devices Container Constructor (derived from dict)

        Calls Super-Constructor for dict and saves a compiled regular expression.
        """
        super(Devices, self).__init__()
        import re  # Regular Expression
        self._pathcheck = re.compile("[\"|\'].*[\"|\']")  # Check via RegEx if String is a Path
        # Prevents Recompile for each use of pathfix

    def fixed_path(self, path):
        # type: (str) -> str
        """Returns a space-protected path-string

        :type path: str
        :param path: input path

        :rtype: str
        :return: space-protected quoted path
        """
        if self._pathcheck.match(path) is None:
            return "\"{}\"".format(path)
        return path

    def add(self, device_id, device_name, device_path, cluster_size=0):
        # type: (int, str, str, int) -> None
        """Adds (or overrides) a Device-Entry with 'devicenr' as key.

        :type device_id: int
        :param device_id: unique device number (also ordering)

        :type device_name: str
        :param device_name: name

        :type device_path: str
        :param device_path: path (formatted via pathfix)

        :type cluster_size: int
        :param cluster_size: optional cluster_size (defaults to 0)
        """
        self[device_id] = (device_id, device_name, self.fixed_path(device_path), cluster_size)


class Options(dict):
    """Container for Options (derived from dict)

    Properties are usually set in an configuration.py (default config-filename) or overridden in main.py via arguments.
    """

    def __init__(self):
        super(Options, self).__init__()
        # self["digests"] = {"SHA1": True}  # type: dict
        self.enable_sha1 = False  # type: bool
        self.enable_sha256 = False  # type: bool
        self.enable_md5 = False  # type: bool
        self.create_archive = True  # type: bool
        self.tempDir = None  # type: str
        self.archive_location = None  # type: str
        self.store_slack_space = False  # type: bool
        self.collect = True  # type: bool
        self.number_threads = 1  # type: int
        self.log_level = logging.NOTSET  # type: logging
        self.log_format = None  # type: str
        self.log_to_file = None  # type: bool
        self.unique_elements_chunk_size = -1  # type: int
        self.hash_chunk_size = 65536  # type: int

    def get_digests_triple(self):
        return self.enable_sha1, self.enable_sha256, self.enable_md5

    def _get(self, key):
        # type: (str) -> Any
        try:
            return self[key]
        except KeyError:
            return None

    def _set(self, key, value):
        # type: (str, Any) -> None
        self[key] = value

    def _set_dict(self, key, *values):
        # type: (str, dict) -> None
        for set_of_values in values:
            for value in set_of_values:
                if value.upper() == "SHA1":
                    self.enable_sha1 = True
                elif value.upper() == "SHA256":
                    self.enable_sha256 = True
                elif value.upper() == "MD5":
                    self.enable_md5 = True
                else:
                    raise AttributeError("digest '{}' is unknown".format(value))
                    # self["digests"][value] = True

    def _del(self, key):
        # type: (str) -> None
        del self[key]

    # Digest Set
    digests = IndexedProperty(_get, _set_dict, _del, "digests")
    # Numeric Settings
    number_threads = IndexedProperty(_get, _set, _del, "number_threads")
    unique_elements_chunk_size = IndexedProperty(_get, _set, _del, "unique_elements_chunk_size")
    hash_chunk_size = IndexedProperty(_get, _set, _del, "hash_chunk_size")
    # Directories
    archive_location = IndexedProperty(_get, _set, _del, "archive_location")
    # Boolean Settings
    enable_sha1 = IndexedProperty(_get, _set, _del, "enable_sha1")
    enable_sha256 = IndexedProperty(_get, _set, _del, "enable_sha256")
    enable_md5 = IndexedProperty(_get, _set, _del, "enable_md5")
    create_archive = IndexedProperty(_get, _set, _del, "create_archive")
    store_slack_space = IndexedProperty(_get, _set, _del, "archive_slack_space")
    collect = IndexedProperty(_get, _set, _del, "collect")
    # Logging relevant Data
    log_level = IndexedProperty(_get, _set, _del, "log_level")
    log_format = IndexedProperty(_get, _set, _del, "log_format")
    log_to_file = IndexedProperty(_get, _set, _del, "log_to_file")


# Allocate Resources if this file is loaded as Module "core.settings"
# Also Prevents unwanted allocation if invoked as "__main__" (e.g. Sphinx Documentation Behaviour)
if __name__ == "pyddup.core.settings":
    devices = Devices()
    options = Options()

if __name__ == "__main__":
    pass
