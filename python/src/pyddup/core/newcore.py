#!/usr/bin/python
#
# Deduplication Abstract Classes

# Python 2 & 3 Compatibility
# Compatibility for Python 2.7+ and 3.5+
# Source: https://wiki.python.org/moin/PortingToPy3k/BilingualQuickRef
from __future__ import absolute_import  # default in python3
from __future__ import division  # non-truncating division ( use // for floor divison)
from __future__ import print_function  # print() function (default in python3) instead of builtin
from __future__ import unicode_literals  # unadorned string literals are unicode per default (default in python3)

from hashlib import sha1, sha256, md5  # hashlib for generating hashCodes from chunks of data
from os import name as os_name  # renamed os.name to prevent confusion with other "names"
from os import path, walk

from pyddup.core.abstracts import DataStore
from pyddup.core.abstracts import FileArchiver
from pyddup.core.settings import Devices
from pyddup.core.settings import Options
from pyddup.core.util import future_decoding_buffer
from pyddup.core.util import logger

# Sphinx Docformat Declaration
__docformat__ = 'reStructuredText'

"""
DeDuplication Methods for the Digital Forensics Tool.
Methods range from validation of the configuration (DataStore, Options, Devices, FileArchiver)
to collecting, processing and archiving files.
Also contains a method to regenerate configuration.py (although with default settings).
"""


def validate_data_store(data_store):
    # type: (DataStore) -> None
    """Checks whether ata_store is a valid implementation of the Abstract Class "DataStore".

    :type data_store: DataStore
    :param data_store: DataStore-Object in Question

    Raises SystemExit if not valid.
    """
    if not isinstance(data_store, DataStore):
        raise SystemExit("Illegal DataStore Instance")
    logger.info("Using {}".format(data_store.__class__.__name__))


def validate_options(options):
    # type: (Options) -> None
    """Checks whether options is valid (either an instance of Options or a Subclass).

    :type options: Options
    :param options: options-Object in Question

    Raises SystemExit if not valid.
    """
    if not isinstance(options, Options):
        raise SystemExit("Illegal options Instance")
    from os import path
    if options.create_archive and \
            (not options.archive_location or not path.exists(options.archive_location)):
        raise SystemExit("Illegal Options: create_archive is set but archive_location is not set or illegal!")
    logger.info("Using Digests: sha1={}, sha256={}, md5={}".format(*options.get_digests_triple()))


def validate_devices(devices):
    # type: (Devices) -> None
    """Checks whether devices is valid (either an instance of Devices or a Subclass).

    :type devices: Devices
    :param devices: devices-Object in Question

    Raises SystemExit if not valid.
    """
    if not isinstance(devices, Devices):
        raise SystemExit("Illegal devices Instance")
    from os import path
    for device_nr in devices:
        (_, _, dir_path, offset) = devices[device_nr]
        logger.info(devices[device_nr])
        if not path.exists(remove_quotes(dir_path)):
            raise SystemExit("Illegal Device({}): Illegal or unreachable Path '{}'.".format(device_nr, dir_path))
        if offset < 0:
            raise SystemExit("Illegal Device({}): Offset is negative '{}'.".format(device_nr, offset))


# noinspection SpellCheckingInspection
def validate_archiver(archiver):
    # type: (FileArchiver) -> None
    """Checks whether archiver is a valid implementation of the Abstract Class "FileArchiver".

    :type archiver: FileArchiver
    :param archiver: archiver-Object in Question

    Raises SystemExit if not valid.
    """
    if not isinstance(archiver, FileArchiver):
        raise SystemExit("Illegal FileArchiver")
    logger.info("Using {}".format(archiver.__class__.__name__))


def remove_quotes(path_string):
    # type: (str) -> str
    """
    Removes Quotes from a Path (e.g. Space-Protection)

    :type path_string: str
    :param path_string:

    :rtype: str
    :return: unquoted path
    """
    import re
    return re.sub('\"', '', path_string)


def map_options_to_digests(options):
    # type: (Options) -> tuple
    """Maps options digests to hashlib functions

    :type options: Options
    :param options: instance of Options

    :rtype: tuple
    :return: list of hashlib functions
    """
    options.get_digests_triple()
    f_sha1, f_sha256, f_md5 = None, None, None
    if options.enable_sha1 is True:
        f_sha1 = sha1()
    if options.enable_sha256 is True:
        f_sha256 = sha256()
    if options.enable_md5 is True:
        f_md5 = md5()
    return f_sha1, f_sha256, f_md5


def collector(device_id, source_path, data_store, hashlib_functions, get_device_loop_func, read_file_slack_func,
              slack_size=0, chunk_size=0):
    # type: (int, str, DataStore, tuple) -> None
    """Collects and processes all files within the given path.
    This operation will be executed by a single thread.
    Note: data_store has to be in an open state!

    :type device_id: int
    :param device_id: device identifier

    :type source_path: str
    :param source_path: root path of the file collection

    :type data_store: DataStore
    :param data_store: DataStore for storing collected files

    :type hashlib_functions: tuple
    :param hashlib_functions: hashlib triple

    :type slack_size: int
    :param slack_size: non negative block size

    :param chunk_size: int
    :param chunk_size: chunk size for generating hash digests
    """
    raw_drive = get_raw_drive(source_path)
    hash_funcs = hashlib_functions
    logger.info("Device {}: collector \"{}\"".format(device_id, source_path))
    device_loop = get_device_loop_func(source_path)
    for (dir_path, _, filename_list) in walk(source_path):
        for absolute_path in map(lambda fp_filename: path.join(dir_path, fp_filename), filename_list):
            if path.isfile(absolute_path):
                logger.debug("Processing: {}".format(absolute_path))
                hash_sha1, hash_sha256, hash_md5 = calculate_file_hashes(absolute_path, hash_funcs, chunk_size)
                data_store.store_entry(hash_sha1, hash_sha256, hash_md5, device_id, absolute_path,
                                       read_file_slack_func(device_loop, absolute_path, slack_size))
                hash_funcs = refresh_hash_pool(*hashlib_functions)
    logger.info("Device {}: collector completed.".format(device_id))


def refresh_hash_pool(f_sha1, f_sha256, f_md5):
    # type: (Any, Any, Any) -> tuple
    """Refreshes the hash pool generator

    :param f_sha1:

    :param f_sha256:

    :param f_md5:

    :rtype: tuple
    :return: refreshed hash functions
    """
    g_sha1, g_sha256, g_md5 = None, None, None
    if f_sha1 is not None:
        g_sha1 = sha1()
    if f_sha256 is not None:
        g_sha256 = sha256()
    if f_md5 is not None:
        g_md5 = md5()
    return g_sha1, g_sha256, g_md5


def calculate_file_hashes(filename, hash_functions, read_chunk_size=65536):
    # type: (str, tuple, int) -> tuple
    """Calculates the files hashes, chunk by chunk (to prevent out of memory errors with large files)

    :type filename: str
    :param filename: absolute file path

    :type hash_functions: tuple
    :param hash_functions: triple of hashfunctions

    :type read_chunk_size: int
    :param read_chunk_size: chunk size for reading the file, defaults to 65536

    :rtype: tuple
    :return: tuple of digests
    """
    hash_sha1, hash_sha256, hash_md5 = hash_functions
    with open(filename, "rb") as file:
        for chunk in iter(lambda: file.read(read_chunk_size), b''):
            update_hashes((hash_sha1, hash_sha256, hash_md5), chunk)
    return safe_digest(hash_sha1), safe_digest(hash_sha256), safe_digest(hash_md5)


def update_hashes(hashes, chunk):
    """Updates the hash function with the given chunk if set (i.e. not None)

    :type hashes: tuple
    :param hashes: hash function

    :type chunk: bytes
    :param chunk: data chunk
    """
    for hash_function in hashes:
        if hash_function is not None:
            hash_function.update(chunk)


def read_file_slack(device_loop, file_path, slack_size):
    """Reads the slack space of a given file
    :type device_loop: str
    :param device_loop:

    :type file_path: str
    :param file_path:

    :type slack_size: int
    :param slack_size:
    :return:
    """
    if slack_size <= 0:
        return bytes()
    return read_slack(device_loop, get_slack_block(file_path, device_loop), slack_size)


def assign_get_device_loop():
    """Returns a fucntor depending on the os for accessing the device_loop
    :return: functor(str)
    """

    def empty(value):
        return ""

    import platform
    if platform.system() == "Windows":
        logger.debug("Assigned DeviceLoop function for 'Windows'.")
        return empty
    if platform.system() == "Linux":
        logger.debug("Assigned DeviceLoop function for 'Linux'.")
        return get_device_loop_linux
    else:
        logger.debug("Assigned DeviceLoop fallback function for unsupported.")
        return empty


def assign_read_file_slack():
    """Returns a functor depending on the OS for reading file slack
    :return: functor(str,int,int)
    """

    def empty(value1, value2, value3):
        return bytes()

    import platform
    if platform.system() == "Windows":
        logger.debug("Assigned ReadFileSlack function for 'Windows'.")
        return empty
    if platform.system() == "Linux":
        logger.debug("Assigned ReadFileSlack function for 'Linux'.")
        return read_file_slack
    else:
        logger.debug("Assigned ReadFileSlack fallback function: unsupported.")
        return empty


def get_device_loop_linux(device_path):
    """Returns blockdevice of the mounted device path

    :type device_path: str
    :param device_path: file path

    :rtype: str
    :return:
    """
    mnt_dev = None
    import subprocess
    subprocess_out = subprocess.check_output(['df', '-h', device_path])
    for line in future_decoding_buffer("UTF-8", subprocess_out).split('\n'):
        if line.startswith("/"):
            mnt_dev = line.partition(" ")[0]
    return mnt_dev


def get_slack_block(file_path, device_loop):
    """Get the last block for the file_path

    :param file_path: target file
    :param device_loop: target device loop
    :return: block sector index offset
    """
    import subprocess
    cmd = 'debugfs -R "blocks ' + file_path + '" ' + device_loop
    logger.debug("Execute command: {}".format(cmd))
    pb_blocks = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stdin=subprocess.PIPE)
    pb_blocks.stdin.close()
    pb_blocks.wait()
    blocks = 0
    for x in pb_blocks.stdout.next().split(" "):
        if not "\n" in x:
            blocks = int(x)
    return blocks


def read_slack(device_loop, block_space, block_size):
    """Reads the slack space and returns the file_slack as byte array.

    :param device_loop: device loop to use read from
    :param block_space: block sector index offset on device loop
    :param block_size: size of a block
    :return: file slack as byte array
    """
    file_slack = bytes()
    if block_size <= 0:
        return file_slack
    try:
        start = (block_space * block_size)
        logger.debug("read_slack({},{},{}), start:{}".format(device_loop, block_space, block_size, start))
        with open(device_loop, 'rb') as handle:
            logger.debug("Accessing Loop[{}] to read slack [{}-{}].".format(device_loop, start, (start + block_size)))
            handle.seek(start)
            file_slack = handle.read(block_size)
    except Exception as e:
        logger.error("Encountered an error while reading file slack: {}".format(e))
    return file_slack


def safe_digest(hash_function):
    # type: (function) -> str
    """Returns the hexdigest if the hash is set (i.e. not None)

    :param hash_function: hash function

    :rtype: str
    :return: hex digest
    """
    if hash_function is not None:
        return hash_function.hexdigest()


def get_raw_drive(filename):
    # type: (str) -> str
    """Returns the RAW Drive for filename (for windows e.g. "C:/")

    :type filename: str
    :param filename: file path

    :rtype: str
    :return:
    """
    return path.splitdrive(filename)[0]


# noinspection SpellCheckingInspection
def archiver(device_id, data_store, archive_service, options, device_sourcepath):
    # type: (int, DataStore, FileArchiver, Options, str) -> None
    """Finds and archives unique files stored in the DataStore.
    This operation will be executed by a single thread.
    Note: data_store and has to be in an open state, archive_service has to be a new instance!

    :type device_id: int
    :param device_id: device identifier

    :type data_store: DataStore
    :param data_store: instance of DataStore

    :type archive_service: FileArchiver
    :param archive_service: instance of FileArchiver

    :type options: Options
    :param options: options

    :type device_sourcepath: str
    :param device_sourcepath: source path, will be removed for the file alias
    """
    from datetime import datetime
    from copy import deepcopy
    from pyddup.core.util import future_encoding
    archive_service = deepcopy(archive_service)  # type: FileArchiver
    archive_name = "archive-{}-{}".format(device_id, datetime.today().strftime("%Y-%m-%d-%H-%M-%S"))
    logger.info("Device {}: archive \"{}\"".format(device_id, archive_name))
    archive_service.provide(options.archive_location, archive_name)
    con_src = len(device_sourcepath)
    for (target_path) in map(lambda el: future_encoding("utf-8", el[0]),
                             data_store.get_uniques_for_device(device_id, options.unique_elements_chunk_size)):
        logger.debug("Archiving: {}".format(target_path))
        archive_service.store_file(target_path, path.abspath(target_path)[con_src + 1:])
    archive_service.close()
    logger.info("Device {}: archive completed.".format(device_id, archive_name))


# noinspection SpellCheckingInspection
def deduplication_pipeline(data_store, archive_service, options, devices):
    # type: (DataStore, FileArchiver, Options, Devices) -> None
    """Deduplication Pipeline
    The deduplication process as single function

    First step: multithreaded file collection (inclusive filehash, slack space) and store it in the DataStore
    Second Step: multithreaded archiving of unique files

    Number of Threads is determined by options.number_threads

    :type data_store: DataStore
    :param data_store: instance of DataStore (e.g. SQLite3DataStore)

    :type archive_service: FileArchiver
    :param archive_service: instance of FileArchiver (ZIP, AFF4)

    :type options: Options
    :param options: Options

    :type devices: Devices
    :param devices: affected Devices
    """
    from multiprocessing.pool import ThreadPool
    async_tasks = {}  # type: dict
    data_store.open()
    if options.collect:
        thread_pool = ThreadPool(processes=options.number_threads)
        get_device_loop_func = assign_get_device_loop()
        read_file_slack_func = assign_read_file_slack()
        for device_id in devices:
            (_, device_name, device_path, cluster_size) = devices[device_id]
            async_tasks[device_id] = thread_pool.apply_async(
                collector,
                (
                    device_id, path.abspath(remove_quotes(device_path)), data_store, map_options_to_digests(options),
                    get_device_loop_func, read_file_slack_func, cluster_size, options.hash_chunk_size,)
            )
        thread_pool.close()
        thread_pool.join()
        for device_id in devices:
            async_tasks[device_id].get()
    if options.create_archive:
        thread_pool = ThreadPool(processes=options.number_threads)
        for device_id in devices:
            (_, device_name, device_path, cluster_size) = devices[device_id]
            async_tasks[device_id] = thread_pool.apply_async(
                archiver,
                (device_id, data_store, archive_service, options, path.abspath(remove_quotes(device_path)),)
            )
        thread_pool.close()
        thread_pool.join()
        for device_id in devices:
            async_tasks[device_id].get()
    data_store.close()


def deduplication_pipeline_single(data_store, archive_service, options, devices):
    """Deduplication pipeline - singlethreaded execution model
    See deduplication_pipeline for the current documentation.
    :param data_store:
    :param archive_service:
    :param options:
    :param devices:
    :return:
    """
    get_device_loop_func = assign_get_device_loop()
    read_file_slack_func = assign_read_file_slack()
    data_store.open()
    for device_id in devices:
        (_, device_name, device_path, cluster_size) = devices[device_id]
        collector(device_id, path.abspath(remove_quotes(device_path)), data_store, map_options_to_digests(options),
                  get_device_loop_func, read_file_slack_func, cluster_size, options.hash_chunk_size)
    for device_id in devices:
        (_, device_name, device_path, cluster_size) = devices[device_id]
        archiver(device_id, data_store, archive_service, options, path.abspath(remove_quotes(device_path)))
    data_store.close()


def access_raw_drive(drive):
    """
    :type drive: str
    :param drive:
    """
    # type: (str) -> None
    if os_name == "posix":
        with open(R"\\.\{}".format(drive), "rb") as drive_access:
            pass
    elif os_name == "nt":
        with open(R"\\.\{}".format(drive), "rb") as drive_access:
            pass
    else:
        raise Exception("Unknown Drive Access for {}".format(os_name))


def regenerate_config(config_path):
    """Generates a new configuration file

    :type config_path: str
    :param config_path: path of the file
    """
    if path.isdir(config_path):
        config_path = path.join(config_path, "configuration.py")
    if not config_path.endswith(".py"):
        config_path += ".py"
    config_py = open(config_path, "w")
    config_py.truncate()
    config_py.write("""
# !/usr/bin/python
#
# Runtime Configuration
# Please edit this file before running main.py
# Also please don't try to execute this file as it is not designed to be executable.

# Execution Protection
# Execute Script only if loaded as module "configuration"
# Prevent's (accidental) execution of Script by some Documentation-Tools (e.g. Sphinx).
if __name__ != "configuration":
    raise SystemExit("Please use this Script only as part of main.py!")

import logging

from pyddup.core.settings import devices, options

########################################################################################################################
# Please edit the Configuration below                                                                                  #
########################################################################################################################

# DataSource provider: must be an implementation of the abstract class DataSource
# Please import your DataStore provider implementation here
# usage:
from pyddup.impl.sqlite3ds import SQLite3DataStore

# Specify the connection properties for the DataStore (ds)
# datastore = SQLite3DataStore("datastore1.db", R"/tmp/", create_clean_db=True, force_create_clean_db=True)
datastore = SQLite3DataStore("datastore1.db", R"/tmp/", create_clean_db=False, force_create_clean_db=False)

# FileArchiver: must be an implementation of the abstract class FileArchiver
# Please import your FileArchiver provider implementation here
# usage:
# from pyddup.impl.aff4archiveprovider import AFF4Archiver
from pyddup.impl.ziparchiveprovider import ZipArchiver

# Specify the FileArchiver (for the reduced Images)
# usage Zip:
# archsvc = ZipArchiver()
# usage AFF4:
# archsvc = AFF4Archiver()
archsvc = ZipArchiver()

# Specify the Number of Threads for Collecting and Archiving
# Default is 1 (if not specified)
# Note: for single threaded execution a simpler pipeline is executed (which is easier to debug)
options.number_threads = 1

# Specify the number of elements which will be loaded from the DataStore in one pass
# defaults to -1, which means all entries will be loaded from the database simultaneously (not recommended)
# depending on your available memory you may increase/decrease this value
options.unique_elements_chunk_size = 5000

# Specify the target devices (Id, Name, Path, Clustersize[optional])
# Id - Unique Numerical Ordering for the device (may be overridden by arguments with the same nr)
# Name - Name for the device (e.g. "SD Card Smartphone")
# Path - Mounted path on your device
# Clustersize - Optional; clustersize of the device
# usage:
# devices.add(DEVICE_NR, DEVICE_DESCRIPTION, PATH_TO_DEVICE [, CLUSTER_SIZE])
# devices.add(1, "SDCard", R"/mnt/sdcard1", 1024)
# devices.add(2, "Drive1", R"/mnt/drivea", 512)
# devices.add(2, "Drive2", R"/mnt/driveb")

# Specify HashDigests you want to use
options.enable_sha1 = True
options.enable_sha256 = False
options.enable_md5 = False

# Specifiy HashChunkSize (the number of bytes read at once in order to calculate the HashDigests)
# Defaults to 65536
options.hash_chunk_size = 65536

# Specify the Location for the archives (has to be a path to a folder), name is specified by the program
# usage:
# options.archive_location = R"/PATH_TO_DIR/"
options.archive_location = "/mnt/c/Temp/"

# Specify whether to store the slack space (or whole file if smaller than the cluster) into the DataStore or not.
# disabled by default
# options.store_slack_space = False #Default
options.store_slack_space = True

# Specify if an archive should be created (archive for each device)
# enabled by default
# options.create_archive = True #Default
options.create_archive = True

# Specify Logging Output:
# logging level:
# options.logLevel = logging.DEBUG
# options.logLevel = logging.INFO
# options.logLevel = logging.WARNING
# options.logLevel = logging.ERROR
# options.logLevel = logging.CRITICAL
options.log_level = logging.DEBUG
# Logging Output Format
# Following keywords will be processed by the logger:
# %(asctime)s - time of event
# %(name)s - name of file
# %(thread)d - id of the thread
# %(threadName)s - name of the thread
# %(levelname)s - log-level
# %(message)s - log-message
options.log_format = '%(asctime)-12s (%(thread)8d:%(threadName)-10s) [%(levelname)6s]: %(message)s'
# Specifies if the log should be duplicated to a file
# location is the same as the archive_location
options.log_to_file = True
########################################################################################################################
# End of Configuration                                                                                                 #
########################################################################################################################
    """)
    config_py.close()
    return config_path
