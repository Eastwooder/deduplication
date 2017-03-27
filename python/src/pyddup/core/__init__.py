from sys import version_info

if version_info.major == 2:
    from pyddup.core.abstracts import *
    from pyddup.core.settings import *
    # from tools import *
    from pyddup.core.util import *