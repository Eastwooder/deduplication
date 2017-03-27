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

"""
FileArchiver implementation for storing Data in the AFF4 Format.
Note: this packages requires PyAFF4 (0.23+), rdflib (4.2.1+, required by PyAFF4)
"""

# Abstract DataStore Provider
from pyddup.core.abstracts import FileArchiver
from pyddup.core.util import logger

import io
import os

from pyaff4 import aff4_directory
# noinspection PyUnresolvedReferences
from pyaff4 import aff4_utils
from pyaff4 import data_store
from pyaff4 import lexicon
from pyaff4 import rdfvalue

# noinspection PyUnresolvedReferences
from pyaff4 import plugins


# Note: if aff4_utils and/or plugins are NOT imported then the AFF4 Library will fail.
# This pitfall may be caused by some IDE's "Autoimport Optimization".
# For PyCharm the "noinspection PyUnresolvedReferences" comment has been added.
# Make sure to keep those imports.

class AFF4Archiver(FileArchiver):
    def __init__(self):
        self.aff4root = None
        self.aff4urn = None
        pass

    def provide(self, location, filename, **metadata):
        if self.aff4root is None:
            self.aff4root = "{}".format(os.path.join(location, filename, ""))
            with data_store.MemoryDataStore() as resolver:
                aff4urn = rdfvalue.URN.NewURNFromFilename(self.aff4root)
                resolver.Set(aff4urn, lexicon.AFF4_STREAM_WRITE_MODE, rdfvalue.XSDString("truncate"))
                with aff4_directory.AFF4Directory.NewAFF4Directory(resolver, aff4urn) as volume:
                    logger.debug("AFF4Directory created with AFF4ROOT = {} and AFF4URN = {}"
                                 .format(self.aff4root, self.aff4urn))
        pass

    def store_file(self, source, alias=None):
        # type: (str, str) -> None
        if alias is None:
            alias = source
        if self.aff4root is not None:
            with data_store.MemoryDataStore() as resolver:
                aff4urn = rdfvalue.URN.NewURNFromFilename(self.aff4root)
                logger.debug("{}".format(aff4urn))
                with aff4_directory.AFF4Directory.NewAFF4Directory(resolver, aff4urn) as volume:
                    file_urn = volume.urn.Append(alias)
                    logger.debug("URN {} created.".format(file_urn))
                    with volume.CreateMember(file_urn) as member:
                        # noinspection PyBroadException
                        fd_stream = None
                        logger.info("Store: {}".format(source))
                        try:
                            fd_stream = io.open(source, mode="rb")
                            member.WriteStream(fd_stream)
                        except (Exception) as e:
                            logger.error("An error has occurred while writing storing \"{}\": {}".format(alias, e))
                        finally:
                            if fd_stream is not None:
                                fd_stream.close()
                        resolver.Set(member.urn, lexicon.AFF4_STREAM_ORIGINAL_FILENAME, rdfvalue.XSDString(alias))
        else:
            raise RuntimeError("Error writing {} into Archive!".format(alias))

    def close(self):
        if self.aff4root is not None:
            self.aff4root = None
