import logging
import sqlite3
import time

class SQLiteManager(object):
    """ Manage various SQLite operations for ATCd
    """
    MC_CREATE_QUERY = \
        'CREATE TABLE IF NOT EXISTS MachineControls('\
        'mac VARCHAR PRIMARY KEY NOT NULL, ip VARCHAR, '\
        'profile_name VARCHAR, is_capturing BOOL,'\
        'is_shaping BOOL, online BOOL, '\
        'last_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, '\
        'FOREIGN KEY (profile_name) REFERENCES `NetworkProfiles`(name))'
    MC_INSERT_WITHTIME_QUERY = \
        'INSERT OR REPLACE INTO MachineControls values (?, ?, ?, ?, ?, ?, ?)'
    MC_DELETE_QUERY = \
        'DELETE FROM MachineControls WHERE mac = ?'
    MC_TABLE_NAME = 'MachineControls'
    MC_MAC_COL = 0
    MC_IP_COL = 1
    MC_PROFILE_COL = 2
    MC_IS_CAPTURING_COL = 3
    MC_IS_SHAPING_COL = 4
    MC_ONLINE_COL = 5
    MC_LASTTIME_COL = 6

    PROFILE_CREATE_QUERY = \
        'CREATE TABLE IF NOT EXISTS NetworkProfiles('\
        'name VARCHAR PRIMARY KEY NOT NULL, tc_setting BLOB)'
    PROFILE_INSERT_QUERY = \
        'INSERT OR REPLACE INTO NetworkProfiles values(?, ?)'
    PROFILE_DELETE_QUERY = \
        'DELETE FROM NetworkProfiles WHERE name = ?'
    PROFILE_TABLE_NAME = 'NetworkProfiles'
    PROFILE_NAME_COL = 0
    PROFILE_TCSETTING_COL = 1

    def __init__(self, file_name, logger=None):
        self.logger = logger or logging.getLogger()
        self.file_name = file_name
        with self._get_conn() as conn:
            conn.execute(SQLiteManager.PROFILE_CREATE_QUERY)
            conn.execute(SQLiteManager.MC_CREATE_QUERY)
        conn.close()

    def get_saved_mcontrols(self):
        """ Querys the db and returns a list of the
            TrafficControl objects that are stored there.
            returns as a list of dicts that have a key for 'mac' and 'tc'
        """
        query = 'SELECT * FROM MachineControls'
        with self._get_conn() as conn:
            results = conn.execute(query).fetchall()
        conn.close()
        # shapings = [{'mac':mac, 'ip':ip, 'state': 1, 'online': TRUE, 'tc': tc_obj, 'last_time': 123456789012}, ... ]
        shapings = []
        for result in results:
            shapings.append(
                {
                    'mac': result[SQLiteManager.MC_MAC_COL],
                    'ip': result[SQLiteManager.MC_IP_COL],
                    'profile_name': result[SQLiteManager.MC_PROFILE_COL],
                    'is_capturing': result[SQLiteManager.MC_IS_CAPTURING_COL],
                    'is_shaping': result[SQLiteManager.MC_IS_SHAPING_COL],
                    'online': result[SQLiteManager.MC_ONLINE_COL],
                    'last_time': result[SQLiteManager.MC_LASTTIME_COL]
                }
            )
        return shapings

    def add_mcontrol(self, mac, ip, profile_name, is_capturing, is_shaping, online, last_update_time):
        with self._get_conn() as conn:
            conn.execute(
                SQLiteManager.MC_INSERT_WITHTIME_QUERY,
                (mac, ip, profile_name, is_capturing, is_shaping, online, last_update_time)
            )
        conn.close()

    def remove_mcontrol(self, mac):
        with self._get_conn() as conn:
            conn.execute(
                SQLiteManager.MC_DELETE_QUERY, 
                (mac,))
        conn.close()

    def get_saved_profiles(self):
        query = 'SELECT * FROM NetworkProfiles'
        with self._get_conn() as conn:
            results = conn.execute(query).fetchall()
        conn.close()
        # profiles = [{'name':name, 'tc':tc_obj}, ...]
        profiles = []
        for result in results:
            profiles.append(
                {
                    'name': result[SQLiteManager.PROFILE_NAME_COL],
                    'tc_setting': result[SQLiteManager.PROFILE_TCSETTING_COL]
                }
            )
        return profiles

    def add_profile(self, name, tc_setting):
        with self._get_conn() as conn:
            conn.execute(
                SQLiteManager.PROFILE_INSERT_QUERY,
                (name, repr(tc_setting)))
        conn.close()

    def remove_profile(self, name):
        with self._get_conn() as conn:
            conn.execute(
                SQLiteManager.PROFILE_DELETE_QUERY, 
                (name,))
        conn.close()

    def _get_conn(self):
        try:
            conn = sqlite3.connect(self.file_name)
        except sqlite3.OperationalError:
            self.logger.error(
                'Unable to access db file: {0}'.format(self.file_name)
            )
            raise
        return conn
