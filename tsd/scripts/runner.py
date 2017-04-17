'''
TrafficShark Daemon main file
'''
from __future__ import absolute_import
from __future__ import print_function

import sys

from tsd.TsdThriftHandlerTask import TsdNBServerTask
from tsd.TsdThriftHandlerTask import TsdThriftHandlerTask
from tsd.TsdVService import TsdVService

# AtcdHandler main class
# from atcd.AtcdDeviceTimeoutTask import AtcdDeviceTimeoutTask
# from atcd.AtcdThriftHandlerTask import AtcdNBServerTask
# from atcd.AtcdThriftHandlerTask import AtcdThriftHandlerTask
# from atcd.AtcdVService import AtcdVService

def initialize_thrift():
    TsdNBServerTask.register()
    TsdThriftHandlerTask.factory().register()
    TsdVService.initFromCLI()

    # AtcdNBServerTask.register()
    # AtcdThriftHandlerTask.factory().register()
    # AtcdDeviceTimeoutTask.register()

    # AtcdVService.initFromCLI()


def run():
    initialize_thrift()
    sys.exit(0)
