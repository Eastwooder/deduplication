#!/usr/bin/python
#

# Python 2 & 3 Compatibility
# Future-Forward compatibility for Python 2.7+
# Source: https://wiki.python.org/moin/PortingToPy3k/BilingualQuickRef
from __future__ import absolute_import  # default in python3
from __future__ import division  # non-truncating division ( use // for floor divison)
from __future__ import print_function  # print() function (default in python3) instead of builtin
from __future__ import unicode_literals  # unadorned string literals are unicode per default (default in python3)

from pyddup.core.newcore import deduplication_pipeline
from pyddup.core.newcore import deduplication_pipeline_single
from pyddup.core.newcore import validate_archiver
from pyddup.core.newcore import validate_data_store
from pyddup.core.newcore import validate_devices
from pyddup.core.newcore import validate_options
from pyddup.core.util import logger
from pyddup.core.util import update_logger

# Sphinx Docformat Declaration
__docformat__ = 'reStructuredText'

"""
DeDuplication Toolchain for Digital Forensics in Python.

Required Packages for the execution of the Toolchain:
    * None

Additional Requirements when using AFF4Archiver:
    * PyAFF4
"""

def device_quadruple(devstr):
    """
    Validates Device-Parameter and returns a quadruple of a device
    """
    import argparse
    try:
        elements = devstr.replace("(", "").replace(")", "").split(",")
        cluster = int(0)
        if elements.__len__() < 3 or elements.__len__() > 4:
            raise argparse.ArgumentTypeError("Device must be (nr:Int,descr:String,target:String[,clustersize:Int])")
        if elements.__len__() == 4:
            cluster = int(elements[3])
        path = elements[2].replace("\"", "").replace("\'", "")
        return int(elements[0]), elements[1], "\"{}\"".format(path), cluster
    except:
        print("Unmatchable String: {}".format(devstr))
        raise argparse.ArgumentTypeError("Device must be (nr:Int,descr:String,target:String[,clustersize:Int])")


# Load as Main
# Also prevents code execution from Sphinx
if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser(usage="""
%(prog)s [args]

(Overrides settings specified in configuration.py)""")
    parser.add_argument('--generateconfig',
                        help='Generate a new configuration.py. Note: if FILEPATH is a directory a configuration.py will be created in there.',
                        nargs='?', dest="filepath", type=str, const="*")
    parser.add_argument('--device',
                        help='Override (or create new) Devices. Format: (id,\'Description\',\'Path\'[,\'Clustersize\'])',
                        dest="devs", nargs='*',
                        type=device_quadruple)
    parser.add_argument('--useconfig', help='Use specified configuration.py instead!', type=str, nargs='?',
                        dest="configlocation")
    parser.add_argument('--onlycollect', help='Only filewalks and adds Entries to the DataStore.', action='store_true')
    parser.add_argument('--onlyarchive', help='Only archives files registered in the DataStore.', action='store_true')
    parser.add_argument('--copyslack', help='Copies the File-Slack of the found files.', action='store_true')
    parser.add_argument('--md5', help='Adds MD5 to the HashDigestSet.', action='store_true')
    parser.add_argument('--sha1', help='Adds SHA1 to the HashDigestSet.', action='store_true')
    parser.add_argument('--sha256', help='Adds SHA256 to the HashDigestSet.', action='store_true')
    in_args = parser.parse_args()

    # Error Prevention
    if in_args.onlycollect and in_args.onlyarchive:
        raise SystemExit("Don't specify onlyanalyze and onlyarchive together, those are exclusive operations!")

    # Generate configuration.py and bail out
    if in_args.filepath:
        fp = in_args.filepath
        if fp == "*":
            from os import getcwd

            fp = getcwd()
        from pyddup.core.newcore import regenerate_config  # (Re)Generate Configuration Py

        fp = regenerate_config(fp)
        raise SystemExit("Configuration created at Location {}".format(fp))

    # Load Configuration either by path or default (local)
    if in_args.configlocation:
        logger.info("Load configuration: {}".format(in_args.configlocation))
        # http://stackoverflow.com/questions/67631/how-to-import-a-module-given-the-full-path
        from imp import load_source

        configuration_module = load_source("configuration", in_args.configlocation)
        # http://stackoverflow.com/questions/9783691/dynamically-importing-python-modules
        for attr in dir(configuration_module):
            if not attr.startswith('_'):
                globals()[attr] = getattr(configuration_module, attr)
    else:
        from configuration import datastore
        from configuration import archsvc
        from configuration import devices
        from configuration import options

    # Update Logger Settings
    if options.log_format is not None:
        log_file_path = None
        if options.log_to_file is True:
            log_file_path = options.archive_location
        update_logger(options.log_format, options.log_level, log_file_path)
        logger.debug("Logger is live!")

    # Override and/or add Devices (by DeviceNr)
    if in_args.devs:
        for dev in in_args.devs:
            devices[dev[0]] = dev

    # Add HashDigests:
    if in_args.sha1:
        options.enable_sha1 = True
    if in_args.sha256:
        options.enable_sha256 = True
    if in_args.md5:
        options.enable_md5 = True

    if in_args.onlycollect:
        options.create_archive = False
        options.collect = True
        logger.info("Collect and Process Only. No Archive!")

    if in_args.onlyarchive:
        options.create_archive = True
        options.collect = False
        logger.info("Archive Only! DataStore must be in agreement with the specified Devices!")

    if in_args.copyslack:
        options.store_slack_space = True

    # Validate Configuration and Input
    logger.debug("DataStore...")
    validate_data_store(datastore)
    logger.debug("ok!")
    logger.debug("Archiver...")
    validate_archiver(archsvc)
    logger.debug("ok!")
    logger.debug("Options...")
    validate_options(options)
    logger.debug("ok!")
    logger.debug("Devices...")
    validate_devices(devices)
    logger.debug("ok!")

    if options.number_threads == 1:
        logger.info("executing in single pipeline (main thread only); reason: number_threads == 1")
        deduplication_pipeline_single(datastore, archsvc, options, devices)
    else:
        logger.info("executing in multithreaded pipeline; reason: number_threads > 1")
        deduplication_pipeline(datastore, archsvc, options, devices)
