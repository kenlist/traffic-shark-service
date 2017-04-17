import logging
import os
import sys

from sparts.vservice import VService


class TsdVService(VService):
    def initLogging(self):
        super(TsdVService, self).initLogging()
        sh = logging.handlers.SysLogHandler(address=self._syslog_address())
        sh.setLevel(logging.DEBUG)
        self.logger.addHandler(sh)
        # Make sparts.tasks logging go to syslog
        sparts_tasks_logger = logging.getLogger('sparts.tasks')
        sparts_tasks_logger.addHandler(sh)

    def _syslog_address(self):
        address = None
        if sys.platform == 'linux2':
            address = '/dev/log'
        elif sys.platform == 'darwin':
            address = '/var/run/syslog'

        if address is None or not os.path.exists(address):
            address = ('localhost', 514)
        return address
