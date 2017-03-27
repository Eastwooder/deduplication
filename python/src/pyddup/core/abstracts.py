#!/usr/bin/python
#
# Deduplication Abstract Classes

# Python 2 & 3 Compatibility
# Compatibility for Python 2.7+ and 3.5+
# Source: https://wiki.python.org/moin/PortingToPy3k/BilingualQuickRef
from __future__ import absolute_import  # default in python3
from __future__ import division  # non-truncating division ( use // for floor division)
from __future__ import print_function  # print() function (default in python3) instead of builtin
from __future__ import unicode_literals  # unadorned string literals are unicode per default (default in python3)

from abc import ABCMeta  # __metaclass__ definition
from abc import abstractmethod  # Annotation for abstract Methods

from pyddup.core.util import Element, future_encoding

# Sphinx Docformat Declaration
__docformat__ = 'reStructuredText'

"""
Interfaces.
"""


class DataStore:
    """
    Abstract DataStore class.
    Abstract Class for implementations of custom DataStores (e.g. different Database, In-Memory Dictionary, ...)
    """
    __metaclass__ = ABCMeta

    @abstractmethod
    def open(self):
        """Open the Connection to the DataStore. Allocate resources.
        """
        pass

    @abstractmethod
    def close(self):
        """Close the connection to the DataStore. Free resources.
        "Close on Success"
        """
        pass

    @abstractmethod
    def abort(self):
        """Close the connection to the DataStore, but aborts all pending operations and rollbacks if applicable.
        Free resources.
        "Close on Failure"
        """
        pass

    @abstractmethod
    def store_entry(self, sha1, sha256, md5, device_id, file_path, file_slack):
        """Write an Entry into the DataStore.
        Those Entries represent found elements.
        Those elements should be stored with minimal store processing overhead.
        (E.g. a Database which holds all those 6-tuple elements without any constraints)

        :type sha1: str
        :param sha1: SHA1 of the Fileobject.

        :type sha256: str
        :param sha256: SHA256 of the Fileobject.

        :type md5: str
        :param md5: MD5 of the Fileobject.

        :type device_id: int
        :param device_id: device identifier (defined via configuration)

        :type file_path: str
        :param file_path: device path + filename + extension

        :type file_slack: bytes
        :param file_slack: byte array representing the last sector
        """
        pass

    def store_element(self, element):
        """Writes an Entry into the DataStore.
        Invokes store_entry but with the elements properties.
        (Non abstract method, no need to override!)

        :type element: Element
        :param element: instance of core.util.Element
        """
        self.store_entry(*(element.morph_to_tuple()))

    @abstractmethod
    def get_uniques_for_device(self, device_id, chunk_size=-1):
        """Returns an iterable (e.g. generator) with all unique entries from the DataStore for the given device_id.

        :type device_id: int
        :param device_id: device identifier

        :type chunk_size: int
        :param chunk_size: defines the size of the chunk (number of elements);
                after chunk is exhausted will load next data;
                returns all if negative (defaults to -1).
                Note: it's not advised to load all elements since there is a high chance that you will run out of memory

        :rtype: list
        :returns: iterable of unique elements (6-tuples representation)
        """
        pass

    def get_uniques_for_device_as_elements(self, device_id, chunk_size=-1):
        for element_instance in map(lambda ntu: Element.morph_from_tuple(None, None, None, *ntu, None),
                                    self.get_uniques_for_device(device_id, chunk_size)):
            yield element_instance

    @staticmethod
    def sanitize_string(codec, element):
        """String sanitizer for e.g. Database Input
        Will call future_encoding which makes sure that the right encoding for the python major version is picked.


        :type codec: str
        :param codec: codec as string

        :type element: str
        :param element: expected to be a string

        :rtype: str
        :return: sanitized element if string, element otherwise
        """
        if isinstance(element, str):
            return future_encoding(codec, element)
        return element

    @staticmethod
    def sanitize_strings(codec, elements):
        """String sanitizer for e.g. Database Input

        :type codec: str
        :param codec: codec as string

        :type elements: list
        :param elements: expected to be a iterable of strings

        :rtype: list
        :return: sanitized element if string, element otherwise
        """
        sanitized_elements = []
        for element in elements:
            sanitized_elements.append(DataStore.sanitize_string(codec, element))
        return sanitized_elements


class FileArchiver:
    """
    Abstract FileArchiver Class
    Abstract Class for archiving files into single containers.
    """
    __metaclass__ = ABCMeta

    @abstractmethod
    def provide(self, location, filename):
        """Provides a FileArchiver in the :location: as :filename:.
        Also sets the state of the object to "open" in order to write Files.

        :type location: str
        :param location: full path (without filename)

        :type filename: str
        :param filename: filename (with extension if applicable)
        """
        pass

    @abstractmethod
    def store_file(self, source, alias=None):
        """Copies a file into the Archive iff this object's state is "open".

        :type source: str
        :param source: full path (with filename) of the source

        :type alias: str
        :param alias: file alias (name of the path), uses source if not set
        """
        pass

    def store_element(self, element, file_alias=None):
        """Copies a file into the Archive iff this object's state is "open".
        (Non abstract method, no need to override!)

        :type element: Element
        :param element: instance of core.util.Element

        :type file_alias: str
        :param file_alias: file alias (name of the path), uses element.file_path if not set
        """
        self.store_file(element.file_path, file_alias)

    @abstractmethod
    def close(self):
        """Closes (and finalizes) the Archive and sets this objects state to "closed"
        :return:
        """
        pass
