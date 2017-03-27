#!/usr/bin/python
#

# Python 2 & 3 Compatibility
# Compatibility for Python 2.7+ and 3.5+
# Source: https://wiki.python.org/moin/PortingToPy3k/BilingualQuickRef
from __future__ import absolute_import  # default in python3
from __future__ import division  # non-truncating division ( use // for floor divison)
from __future__ import print_function  # print() function (default in python3) instead of builtin
from __future__ import unicode_literals  # unadorned string literals are unicode per default (default in python3)

from os import path, getcwd
import threading

from pyddup.core.abstracts import DataStore  # abstract DataStore declaration
from sqlite3 import Connection, connect, OperationalError, Binary

# Sphinx Docformat Declaration

__docformat__ = 'reStructuredText'


class SQLite3DataStore(DataStore):
    """SQLite3 DataStore Implementation
    Stores Elements into a SQLite3 Database.
    """
    # noinspection SpellCheckingInspection
    insert_element = "INSERT INTO elements(SHA1, SHA256, MD5, DEVICEID, PATH, FILESLACK) VALUES(?,?,?,?,?,?)"
    # noinspection SpellCheckingInspection
    query_unique_elements = "SELECT PATH FROM get_unique_elements_all WHERE DEVICEID = ? ORDER BY PATH ASC"

    def __init__(self, db_filename, db_file_path=None, create_clean_db=False, force_create_clean_db=False,
                 write_data_threshold=1000, string_codec="utf-8"):
        # type: (str, str, bool, bool, int) -> None
        """Creates a new SQLite3DataStore (but does not create a connection)

        :type db_filename: str
        :param db_filename: filename of the database without path

        :type db_file_path: str
        :param db_file_path: optional path, if not specified will use current working directory

        :type create_clean_db: bool
        :param create_clean_db: optional boolean, specifies if a create clean database script should be executed on open
                if no database was found

        :type force_create_clean_db: bool
        :param force_create_clean_db: optional boolean, specifies if a new database should be created IN ANY CASE
                Warning: overrides old database with the same name

        :type write_data_threshold: int
        :param write_data_threshold: number of inserts which are to be hold in the memory before flushing into the Database

        :type string_codec: str
        :param string_codec: string encoding used in database (used for sanitize strings)
        """
        if db_file_path is None:  # If no path is specified use current directory as path
            db_file_path = getcwd()
        self.db_file_path = path.join(db_file_path, db_filename)  # type: str
        self.create_db = create_clean_db  # type: bool
        self.force_create_db = force_create_clean_db  # type: bool
        self.db_connection = None  # type: Connection
        self.current_data_runner = 0  # type: int
        self.lock = threading.Lock()  # type: threading.Lock
        if write_data_threshold == 0:
            write_data_threshold = 1000
        elif write_data_threshold < 0:
            write_data_threshold = -write_data_threshold
        self.write_data_threshold = write_data_threshold  # type: int
        self.string_codec = string_codec

    def open(self):
        if self.db_connection is not None:
            return
        # Check if the specified database exists
        db_exists = path.exists(self.db_file_path)
        self.db_connection = connect(self.db_file_path, check_same_thread=False)

        if self.force_create_db or not db_exists:  # Create Database
            if self.force_create_db or self.create_db:
                with open(path.join(getcwd(), "pyddup", "impl", "SQLite3_setup_script.sql"), "rt") as script_reader:
                    sql_create_script = script_reader.read()
                self.db_connection.executescript(sql_create_script)
            else:
                self.db_connection.close()
                raise RuntimeError("SQLite3 Database not found and no create specified!")
        self.db_connection.execute("BEGIN TRANSACTION")  # Performance increase

    def close(self):
        if self.db_connection is None:
            raise RuntimeWarning("SQLite3 connection is already closed!")
        self.db_connection.commit()
        self.db_connection.close()
        self.db_connection = None

    def abort(self):
        if self.db_connection is None:
            raise RuntimeWarning("SQLite3 connection is already closed!")
        self.db_connection.rollback()
        self.db_connection.close()
        self.db_connection = None

    def store_entry(self, sha1, sha256, md5, device_id, file_path, file_slack):
        # type: (str, str, str, int, str, str) -> None
        sha1, sha256, md5, file_path = DataStore.sanitize_strings(self.string_codec, [sha1, sha256, md5, file_path])
        if file_slack is not None:
            file_slack = Binary(file_slack)
        self.db_connection.execute(
            SQLite3DataStore.insert_element,
            (sha1, sha256, md5, device_id, file_path, file_slack,)
        )
        with self.lock:
            self.current_data_runner += 1
            if self.current_data_runner >= self.write_data_threshold:
                self.db_connection.commit()
                self.db_connection.execute("BEGIN TRANSACTION")  # performance increase
                self.current_data_runner -= self.write_data_threshold

    def get_uniques_for_device(self, device_id, chunk_size=-1):
        # type: (int, int) -> generator
        try:
            self.db_connection.commit()  # to finish pending operations
        except OperationalError:  # since non active transaction may cause an error
            pass
        cursor = self.db_connection.cursor()
        cursor.execute(
            SQLite3DataStore.query_unique_elements,
            (device_id,)
        )
        if chunk_size <= 0:
            def fetch():
                return cursor.fetchall()
        else:
            def fetch():
                return cursor.fetchmany(chunk_size)
        while True:
            result_set = fetch()
            if not result_set:
                break
            for result in result_set:
                yield result
