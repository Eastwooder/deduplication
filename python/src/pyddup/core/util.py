#!/usr/bin/python
#
# Utilities, Workaround, Non-Forensic Extensions

# Python 2 & 3 Compatibility
# Compatibility for Python 2.7+ and 3.5+
# Source: https://wiki.python.org/moin/PortingToPy3k/BilingualQuickRef
from __future__ import absolute_import  # default in python3
from __future__ import division  # non-truncating division ( use // for floor division)
from __future__ import print_function  # print() function (default in python3) instead of builtin
from __future__ import unicode_literals  # unadorned string literals are unicode per default (default in python3)

import logging
from sys import version_info

# Sphinx Docformat Declaration
__docformat__ = 'reStructuredText'

"""
Utility Package.
Contains common Classes and Objects which don't belong anywhere else.
Contains Logging, IndexedProperty, Element.
"""


class Element:
    """Container for a 6-tuple representing elements in the DataStore.
    Usually the file_slack will be none when reading from the DataStore since we don't need it for the representation.
    Slotted class, only the 6 tuple representing this class can be assigned:
        :param sha1:
        :param sha256:
        :param md5:
        :param device_id:
        :param file_path:
        :param file_slack:
    __slots__ is used to reduce memory overhead (potential space savings) and faster attribute access.
    """
    __slots__ = ["sha1", "sha256", "md5", "device_id", "file_path", "file_slack"]

    def __init__(self, sha1=None, sha256=None, md5=None, device_id=None, file_path=None, file_slack=None):
        # type: (str, str, str, int, str, bytes)
        """Default Constructor with no values set

        :type sha1: str
        :param sha1: SHA1 Hash

        :type sha256: str
        :param sha256: SHA256 Hash

        :type md5: str
        :param md5: MD5 Hash

        :type device_id: int
        :param device_id: Device Identifier

        :type file_path: str
        :param file_path: File Path

        :type file_slack: bytes
        :param file_slack: File Slack
        """
        self.sha1 = sha1
        self.sha256 = sha256
        self.md5 = md5
        self.device_id = device_id
        self.file_path = file_path
        self.file_slack = file_slack

    def __call__(self):
        """Morphs this instance into a tuple
        :return: morph_to_tuple
        """
        return self.morph_to_tuple()

    def morph_to_tuple(self):
        # type: () -> tuple
        """Returns the instance of Element as (6)-tuple

        :rtype: tuple
        :return: tuple(sha1, sha256, md5, device_id, file_path, file_slack)
        """
        return self.sha1, self.sha256, self.md5, self.device_id, self.file_path, self.file_slack

    @staticmethod
    def morph_from_tuple(sha1, sha256, md5, device_id, file_path, file_slack):
        """Creates a new instance of Element, see constructor
         :type sha1: str
        :param sha1: SHA1 Hash

        :type sha256: str
        :param sha256: SHA256 Hash

        :type md5: str
        :param md5: MD5 Hash

        :type device_id: int
        :param device_id: Device Identifier

        :type file_path: str
        :param file_path: File Path

        :type file_slack: bytes
        :param file_slack: File Slack

        :rtype: Element
        :return: Element Instance of File
        """
        return Element(sha1, sha256, md5, device_id, file_path, file_slack)


class IndexedProperty(object):
    """Workaround for properties managed by a dict.

    Works the same as the builtin 'property' equivalent with the difference that the getter/setter/deleter methods
    use a key to determine the local attribute (i.e. different than assigned properties).
    Based on the native 'property' builtin equivalent: https://docs.python.org/2/howto/descriptor.html#properties
    """

    def __init__(self, f_get=None, f_set=None, f_del=None, f_key=None, doc=None):
        self.f_get = f_get
        self.f_set = f_set
        self.f_del = f_del
        self.f_key = f_key
        if doc is None and f_get is not None:
            doc = f_get.__doc__
        self.__doc__ = doc

    def __get__(self, obj, objtype=None):
        if obj is None:
            return self
        if self.f_get is None:
            raise AttributeError("unreadable attribute")
        return self.f_get(obj, self.f_key)

    def __set__(self, obj, value):
        if self.f_set is None:
            raise AttributeError("can't set attribute")
        self.f_set(obj, self.f_key, value)

    def __delete__(self, obj):
        if self.f_del is None:
            raise AttributeError("can't delete attribute")
        self.f_del(obj, self.f_key)

    def getter(self, p_get):
        return type(self)(p_get, self.f_set, self.f_del, self.f_key, self.__doc__)

    def setter(self, p_set):
        return type(self)(self.f_get, p_set, self.f_del, self.f_key, self.__doc__)

    def deleter(self, p_del):
        return type(self)(self.f_get, self.f_set, p_del, self.f_key, self.__doc__)

    def key(self, p_key):
        return type(self)(self.f_get, self.f_set, self.f_del, p_key, self.__doc__)


logger = logging.getLogger()
logger_stdout_handler = logging.StreamHandler()
logger_file_handler = None  # type: logging.FileHandler
logger_formatter = logging.Formatter('%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
logger_stdout_handler.setFormatter(logger_formatter)
logger.addHandler(logger_stdout_handler)
logger.setLevel(logging.INFO)


def update_logger(log_format, log_level, log_dir=None):
    from os import path
    from datetime import datetime
    """Updates the logger object with a new format and Level
    :param log_format: new logformat
    :param log_level: new loglevel
    :param log_dir: Directory Path for logging
    :return: none
    """
    global logger_file_handler
    logger.removeHandler(logger_stdout_handler)
    if logger_file_handler is not None:
        logger.removeHandler(logger_file_handler)
    formatter_handler = logging.Formatter(log_format)
    logger_stdout_handler.setFormatter(formatter_handler)
    logger.addHandler(logger_stdout_handler)
    if log_dir is not None:
        logger_file_handler = logging.FileHandler(
            path.join(log_dir, "deduplication.{}.log".format(datetime.today().strftime("%Y-%m-%d.%H-%M-%S")))
        )
        logger_file_handler.setFormatter(formatter_handler)
        logger.addHandler(logger_file_handler)
    logger.setLevel(log_level)
    logger.info("Updated Logger: \nLevel = {}\nFormat = {}\nDirectory = {}"
                .format(log_level, log_format, log_dir))


def future_encoding(codec, element):
    """Future-proof encoding for Python 2.x and 3.x (as of 01.12.2016)

    :type codec: str
    :param codec: codec

    :type element: str
    :param element: element to be encoded

    :rtype: str
    :return: encoded element (str or unicode, depending on python version)
    """
    if version_info.major == 2:
        if isinstance(element, str):
            return element.decode(codec)
        return element.encode(encoding=codec, errors="ingore")
    elif version_info.major == 3:
        if isinstance(element, bytes):
            return bytes(element)
        return element.encode(encoding=codec, errors="ignore")
    return element


def future_decoding_buffer(codec, element):
    """
    :param codec:
    :param element:
    :return:
    """
    if version_info.major == 3:
        return element.decode("UTF-8")
    return element

if __name__ == 'pyddup.core.util':  # Load as Module
    pass
