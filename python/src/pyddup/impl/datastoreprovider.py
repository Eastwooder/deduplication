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
from pyddup.core.abstracts import DataStore


class MemoryDataStore(DataStore):
    def __init__(self):
        self.unique = {}
        self.duplicate = []

    def open(self):
        pass

    def close(self):
        pass

    def abort(self):
        pass

    def read(self, sha1):
        try:
            return self.unique[sha1]
        except:
            return None

    def writeEntry(self, sha1, sha256, md5, device_id, filepath, lastCluster = None):
        self.unique[sha1] = (sha1, sha256, md5, device_id, filepath)

    def writeDuplicate(self, sha1, device_id, filepath):
        self.duplicate.append((sha1, device_id, filepath))

    def getUniques(self, device_id):
        for val in self.unique:
            (sha1, sha256, md5, devid, filepath) = self.unique[val]
            if devid == device_id:
                yield (sha1, sha256, md5, devid, filepath)


import mysql.connector

from pyddup.core.util import logger

class MySQLDataStore(DataStore):
    def __init__(self, dsconfig):
        self.dsconfig = dsconfig
        self.insertentry = ("INSERT INTO found(SHA1,SHA256,MD5,DEVICE,PATH,LASTSEGMENT) VALUES(%s, %s, %s, %s, %s, %s)")
        self.insertduplicate = ("INSERT INTO duplicate(SHA1,DEVICE,PATH) VALUES(%s, %s, %s)")
        # self.querytemplate = ("SELECT SHA1 FROM found AS f WHERE f.SHA1 = '%s'")
        self.querytemplate = (
            "SELECT 1 FROM dual WHERE exists (select f.SHA1 FROM found AS f WHERE f.SHA1 = '%s') or exists(select w.SHA1 FROM whitelist AS w WHERE w.SHA1 = '%s')"
        )
        self.uniques = ("SELECT SHA1,SHA256,MD5,DEVICE,PATH FROM found WHERE DEVICE = %s")

    def open(self):
        self.connection = mysql.connector.connect(**self.dsconfig)
        self.cursor = self.connection.cursor(buffered=True)

    def close(self):
        self.connection.commit()
        self.cursor.close()
        self.connection.close()

    def abort(self):
        self.connection.rollback()
        self.cursor.close()
        self.connection.close()

    def read(self, sha1):
        self.cursor.execute(self.querytemplate % (sha1, sha1))
        for (SHA1) in self.cursor:
            return SHA1
        return None

    def writeEntry(self, sha1, sha256, md5, device_id, filepath, lastCluster=None):
        try:
            self.cursor.execute(self.insertentry, (sha1, sha256, md5, device_id, filepath, lastCluster))
        except (Exception) as e:
            logger.error('Entry for key ntupel already in database: %s' % (filepath))

    def writeDuplicate(self, sha1, deviceid, filepath):
        self.cursor.execute(self.insertduplicate, (sha1, deviceid, filepath))

    def getUniques(self, deviceid):
        self.cursor.execute(self.uniques % (deviceid))
        for (sha1, sha256, md5, device, path) in self.cursor:
            yield (sha1, sha256, md5, device, path)