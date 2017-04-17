from sqlite3 import OperationalError
from tsd.db_manager import SQLiteManager
from sparts.sparts import option
from sparts.tasks.queue import QueueTask


class TsdDBQueueTask(QueueTask):
    OPT_PREFIX = 'sqlite'
    workers = 1

    # DEFAULT_SQLITE_FILE = '/var/lib/atcd.db'
    DEFAULT_SQLITE_FILE = '/home/pi/traffic-shark-service/tsd.db'

    sqlite_file = option(
        default=DEFAULT_SQLITE_FILE,
        metavar='SQLITE_FILE',
        help='Location to store the sqlite3 db [%(default)s]',
        name='file',
    )

    def initTask(self):
        super(TsdDBQueueTask, self).initTask()
        try:
            self.sqlite_manager = SQLiteManager(self.sqlite_file, self.logger)
        except OperationalError:
            self.logger.exception(
                'Unable to initialize DB from file "{0}"'.format(
                    self.sqlite_file
                )
            )
            raise

    def execute(self, item, context):
        try:
            obj, action = item
        except ValueError:
            self.logger.exception('Error executing on item: {0}'.format(item))
            return
        try:
            func = getattr(self.sqlite_manager, action)
        except AttributeError:
            self.logger.exception(
                'unable to run action, {0}, no such method'.format(action)
            )
            raise
        try:
            if isinstance(obj, tuple):
                func(*obj)
            else:
                func(obj)
        except OperationalError:
            self.logger.exception("Unsupported operation")
            return

    def get_saved_profiles(self):
        return self.sqlite_manager.get_saved_profiles()

    def get_saved_mcontrols(self):
        return self.sqlite_manager.get_saved_mcontrols()