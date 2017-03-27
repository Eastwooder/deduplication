#!/usr/bin/python
#

# Python 2 & 3 Compatibility
# Compatibility for Python 2.7+ and 3.5+
# Source: https://wiki.python.org/moin/PortingToPy3k/BilingualQuickRef
from __future__ import absolute_import  # default in python3
from __future__ import division  # non-truncating division ( use // for floor divison)
from __future__ import print_function  # print() function (default in python3) instead of builtin
from __future__ import unicode_literals  # unadorned string literals are unicode per default (default in python3)

# Sphinx Docformat Declaration
__docformat__ = 'reStructuredText'

# Abstract DataStore Provider
from pyddup.core.abstracts import FileArchiver
import zipfile
from os import path
from pyddup.core.util import future_decoding_buffer
from sys import version_info


class ZipArchiver(FileArchiver):
    def __init__(self):
        self.zip_file_ptr = None

    def provide(self, location, filename, **metadata):
        # type: (str, str, dict) -> None
        if self.zip_file_ptr is None:
            self.zip_file_ptr = zipfile.ZipFile("{}.zip".format(path.join(location, filename)), "w",
                                                zipfile.ZIP_DEFLATED, True)
        else:
            raise RuntimeError("Cannot create Archive: {}".format(path.join(location, filename)))
        pass

    def store_file(self, source, alias=None):
        # type: (str, str) -> None
        if alias is None:
            alias = source
        if self.zip_file_ptr is not None:
            self.zip_file_ptr.write(self.version_safe_zip_string(source),
                                    self.version_safe_zip_string(alias))
        else:
            raise RuntimeWarning("Error writing {} into Archive: not provided!".format(alias))

    def close(self):
        if self.zip_file_ptr is not None:
            self.zip_file_ptr.close()
        else:
            raise RuntimeWarning("Error while closing Archive!")
        pass

    def version_safe_zip_string(self, element):
        if version_info.major == 3:
            return element.decode("UTF-8")
        return element
