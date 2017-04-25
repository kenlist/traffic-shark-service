#!/usr/bin/env python
import os
import logging
import logging.handlers
import socket
import subprocess
import shlex
import time
import threading
from subprocess import Popen
from functools import wraps
from sqlite3 import OperationalError

from sparts.tasks.thrift import NBServerTask
from sparts.tasks.thrift import ThriftHandlerTask
from sparts.sparts import option

from traffic_shark_thrift import TrafficSharkService

# TrafficShark thrift files
import traffic_shark_thrift.ttypes
from traffic_shark_thrift.ttypes import ReturnCode
from traffic_shark_thrift.ttypes import TrafficControlException
from traffic_shark_thrift.ttypes import TrafficControlRc
from traffic_shark_thrift.ttypes import Profile, MachineControl, MachineControlState

from tsd.idmanager import IdManager
from tsd.TsdDBQueueTask import TsdDBQueueTask
from tsd.TsdScapyTask import TsdScapyTask

from tsd.packet_to_json import PacketsToJson

def from_module_import_class(modulename, classname):
    klass = getattr(
        __import__(modulename, globals(), locals(), [classname], -1),
        classname
    )
    globals()[classname] = klass

class TsdNBServerTask(NBServerTask):
    """Tsd Non Blocking Thrift server.

    Overrides sparks' Non blocking thrift server defaults for Tsd use.
    """
    DEFAULT_PORT = 9090
    DEFAULT_HOST = '0.0.0.0'

def address_check(method):
    @wraps(method)
    def decorator(self, mac):
        if not self._machine_controls.get(mac):
            # can not shape while not exist
            return TrafficControlRc(
                code=ReturnCode.INVALID_ADDRESS,
                message="Invalid Address {mac:{0}}".format(mac))

        mc = self._machine_controls[mac]

        try:
            socket.inet_aton(mc['ip'])
        except Exception as e:
            return TrafficControlRc(
                code=ReturnCode.INVALID_ADDRESS,
                message="Invalid IP {0} for mac:{1}".format(mc['ip'], mac))
        return method(self, mac, mc)
    return decorator

class TsdThriftHandlerTask(ThriftHandlerTask):
    DEFAULT_LAN = 'wlan0'
    DEFAULT_WAN = 'eth0'
    DEFAULT_IPTABLES = '/sbin/iptables'
    DEFAULT_BURST_SIZE = 12000

    MODULE = TrafficSharkService
    DEPS = [TsdDBQueueTask, TsdScapyTask]
    OPT_PREFIX = 'tsd'

    lan_name = option(
        default=DEFAULT_LAN,
        metavar='LAN',
        help='name of the LAN interface [%(default)s]',
        name='lan',
    )
    wan_name = option(
        default=DEFAULT_WAN,
        metavar='WAN',
        help='name of the WAN interface [%(default)s]',
        name='wan',
    )
    iptables = option(
        default=DEFAULT_IPTABLES,
        metavar='IPTABLES',
        help='location of the iptables binary [%(default)s]'
    )
    burst_size = option(
        default=DEFAULT_BURST_SIZE,
        metavar='BURST_SIZE',
        type=int,
        help='Amount of bytes that can be burst at a capped speed '
                '[%(default)s]'
    )
    dont_drop_packets = option(
        action='store_true',
        help='[EXPERIMENTAL] Do not drop packets when going above max allowed'
             ' rate. Packets will be queued instead. Please mind that this'
             ' option will likely disappear in the future and is only provided'
             '  as a workaround until better longer term solution is found.',
    )

    @staticmethod
    def factory():
        os_name = os.uname()[0]
        klass = 'Tsd{0}Shaper'.format(os_name)

        try:
            if klass not in globals():
                from_module_import_class(
                    'tsd.backends.{0}'.format(os_name.lower()), klass
                )
        except AttributeError:
            raise NotImplementedError('{0} is not implemented!'.format(klass))
        except ImportError:
            raise NotImplementedError(
                '{0} backend is not implemented!'.format(os_name.lower())
            )
        return globals()[klass]

    def initTask(self):
        super(TsdThriftHandlerTask, self).initTask()
        print "[start initTask]"

        self.db_task = self.service.tasks.TsdDBQueueTask
        self.scapy_task = self.service.tasks.TsdScapyTask
        self.scapy_task.setupIface(self.lan_name)

        self.lan = {'name': self.lan_name}
        self.wan = {'name': self.wan_name}
        self._links_lookup()

        self.initialize_id_manager()
        self.initialize_shaping_system()

        # Map of MAC address to tc object that is currently
        # being used to shape traffic from that device.
        # {mac: {'ip': ip, 'tc': tc, 'is_shaping': True/False, online: True/False, 'last_time': timestamp}}
        # {'AB:CD:EF:GH:9O': {'ip': "172.1.44.3", 'tc': TrafficControl(...), 'is_shaping': True, online: True, 'last_time': 1234567890123}}
        self._machine_controls = {}
        self._machine_shapings = {}

        # Map of profile that is saved
        # {id: {'name': name, 'tc_setting': tc_setting}, ...}
        # {1: {'name': 'test', 'tc_setting': TrafficControlSetting(...)}, ...}
        self._profiles = {}

        self.logger.info('Restoring shaped & profile connection from DB')
        self._restore_saved_profiles()
        self._restore_saved_mcontrols()

    def initialize_id_manager(self):
        """Initialize the Id Manager. This is architecture dependant as the
        shaping subsystems may have different requirements.
        """
        self.idmanager = IdManager(
            first_id=type(self).ID_MANAGER_ID_MIN,
            max_id=type(self).ID_MANAGER_ID_MAX
        )

    def initialize_shaping_system(self):
        """Initialize the shaping subsystem.

        Each shaping platform should implement its own.
        """
        raise NotImplementedError('Subclass should implement this')

    def _restore_saved_profiles(self):
        """Restore the profiles from the sqlite3 db.
        """
        # Isolate the things we are using eval on to reduce possible clownyness
        # later on, also this way we don't have unused imports from importing
        # blindly for eval
        names = [
            'Shaping', 'Profile',
            'TrafficControlSetting', 'Loss', 'Delay', 'Corruption', 'Reorder'
        ]
        globals = {name: getattr(traffic_shark_thrift.ttypes, name) for name in names}

        result = []
        try:
            results = self.db_task.get_saved_profiles()
        except OperationalError:
            self.logger.exception('Unable to perform DB operation')
        # self.logger.info("profiles:{0}".format(results))
        for result in results:
            profile_name = result['name']
            profile_tc_setting = eval(result['tc_setting'], globals)
            self._profiles[profile_name] = profile_tc_setting

    def _restore_saved_mcontrols(self):
        """Restore the shapings from the sqlite3 db.
        """
        # Isolate the things we are using eval on to reduce possible clownyness
        # later on, also this way we don't have unused imports from importing
        # blindly for eval
        names = [
            'Shaping',
            'TrafficControlSetting', 'Loss', 'Delay', 'Corruption', 'Reorder'
        ]
        globals = {name: getattr(traffic_shark_thrift.ttypes, name) for name in names}

        result = []
        try:
            results = self.db_task.get_saved_mcontrols()
        except OperationalError:
            self.logger.exception('Unable to perform DB operation')
        for result in results:
            mac = result['mac']
            self._machine_controls[mac] = {
                'mac': result['mac'],
                'ip': result['ip'],
                'profile_name': result['profile_name'],
                'is_capturing': result['is_capturing'],
                'is_shaping': result['is_shaping'],
                'online': result['online'],
                'last_update_time': result['last_time']
            }

        for mac in self._machine_controls:
            mc = self._machine_controls[mac]
            if mc['is_shaping']:
                self.shapeMachine(mac)
            if mc['is_capturing']:
                self.startCapture(mac)

    def run_cmd(self, cmd):
        self.logger.info("Running {}".format(cmd))
        return subprocess.call(shlex.split(cmd))

    # Profiles
    def _profile_instance(self, name, settings):
        return Profile(
            name=name,
            tc_setting=settings,
        )

    def getProfiles(self):
        self.logger.info('Request getProfiles')
        # print self._profiles

        return [
            self._profile_instance(name, settings) for name, settings in self._profiles.items()
        ]

    def addProfile(self, profile):
        self.logger.info('Request addProfile for name {0}'.format(profile.name))
        self.db_task.queue.put(((profile.name, profile.tc_setting), 'add_profile'))
        self._profiles[profile.name] = profile.tc_setting

        mac_list = []
        for mac in self._machine_shapings:
            mshaping = self._machine_shapings[mac]
            if mshaping['profile_name'] == profile.name:
                mac_list.append(mac)

        for mac in mac_list:
            self.shapeMachine(mac)  # reshape

        return TrafficControlRc(code=ReturnCode.OK)

    def removeProfile(self, name):
        self.logger.info('Request removeProfile for name {0}'.format(name))
        self.db_task.queue.put((name), 'remove_profile')
        del self._profiles[name]
        return TrafficControlRc(code=ReturnCode.OK)

    # Machine Controls
    def _scanAddress(self):
        addr_str = os.popen("arp -a | grep -v incomplete | grep wlan0 | awk '{print \"{\\\"ip\\\":\\\"\"substr($2, 2, length($2) - 2)\"\\\",\\\"mac\\\":\\\"\"$4\"\\\"}\"}'").read()
        addr_list = [eval(addr) for addr in addr_str.split('\n') if addr]

        self.logger.info(
            "Scan address list:{0}".format(addr_list)
        )
        return addr_list

    def _mc_instance(self, mac, state):
        return MachineControl(
            mac=mac,
            state=MachineControlState(
                ip=state.get('ip'),
                profile_name=state.get('profile_name'),
                is_capturing=state.get('is_capturing'),
                is_shaping=state.get('is_shaping'),
                online=state.get('online'),
                last_update_time=state.get('last_update_time'),
            )
        )

    def getMachineControls(self):
        self.logger.info('Request getMachineControls')

        addr_list = self._scanAddress()

        new_machine_controls = {}
        now = int(round(time.time() * 1000))

        for addr in addr_list:
            mac = addr["mac"]
            ip = addr["ip"]

            if self._machine_controls.get(mac):
                # already has the mac addr
                mc = self._machine_controls[mac]
                mc['mac'] = mac
                mc['ip'] = ip
                mc['online'] = True
                mc['last_update_time'] = now

                # add to new_machine_controls & remove old mapping
                new_machine_controls[mac] = mc 
                self._update_mcontrol(mc)
                del self._machine_controls[mac]
            else:
                # add the shaping
                mc = {
                    "mac": mac,
                    "ip": ip,
                    "is_capturing": False,
                    "is_shaping": False,
                    "online": True,
                    "last_update_time": now
                }
                new_machine_controls[mac] = mc
                self._update_mcontrol(mc)

        for mac in self._machine_controls:
            self.unshapeMachine(mac)
            mc = self._machine_controls[mac]

            # check time out, limit 2 days
            if now - mc['last_update_time'] > 2 * 24 * 60 * 60 * 1000:
                self.db_task.queue.put(((mac), 'remove_mcontrol'))
            else:
                mc['online'] = False
                mc['ip'] = ''
                self._update_mcontrol(mc)
                new_machine_controls[mac] = mc
            
        self._machine_controls = new_machine_controls
        self.logger.info("machine controls:{0}".format(self._machine_controls))

        return [
            self._mc_instance(mac, state) for mac, state in self._machine_controls.items()
        ]

    def updateMachineControl(self, update_mc):
        if not self._machine_controls.get(update_mc.mac):
            # can not update while not exist
            return TrafficControlRc(
                code=ReturnCode.INVALID_ADDRESS,
                message="Invalid Address {mac:{0}, ip:{1}}".format(update_mc.mac, update_mc.state.ip))

        mc = self._machine_controls[update_mc.mac]

        # update profile_name only for now
        mc['profile_name'] = update_mc.state.profile_name
        self._update_mcontrol(mc)

        # update profiles while shaping
        if mc['is_shaping']:
            return self.shapeMachine(update_mc.mac)

        return TrafficControlRc(code=ReturnCode.OK)

    @address_check
    def shapeMachine(self, mac, mc):
        # remove old interface
        if self._machine_shapings.get(mac):
            # update shapings
            old_shaping = self._machine_shapings[mac]
            old_id = old_shaping['id']
            self._unshape_interface(old_id, self.wan, old_shaping['ip'], old_shaping['tc'].up)
            self._unshape_interface(old_id, self.lan, old_shaping['ip'], old_shaping['tc'].down)
            self.idmanager.free(old_id)
            del self._machine_shapings[mac]

        # get profile setting
        setting = self._profiles.get(mc.get('profile_name'))
        if setting is None:
            return TrafficControlRc(
                code=ACCESS_DENIED,
                message="Invalid profile name: {0}".format(mc['profile_name']))

        new_id = None
        try:
            new_id = self.idmanager.new()
        except Exception as e:
            return TrafficControlRc(
                code=ReturnCode.ID_EXHAUST,
                message="No more session available: {0}".format(e))

        self._machine_shapings[mac] = {
            'id': new_id,
            'ip': mc['ip'],
            'tc': setting,
            'profile_name': mc.get('profile_name')
        }

        # do shape
        tcrc = self._shape_interface(new_id, self.wan, mc['ip'], setting.up)
        if tcrc.code != ReturnCode.OK:
            return tcrc
        tcrc = self._shape_interface(new_id, self.lan, mc['ip'], setting.down)
        if tcrc.code != ReturnCode.OK:
            self._unshape_interface(new_id, self.wan, mc['ip'], setting.up)
            return tcrc
        mc['is_shaping'] = True
        self._update_mcontrol(mc)

        return TrafficControlRc(code=ReturnCode.OK)

    def unshapeMachine(self, mac):
        # remove old interface
        if self._machine_shapings.get(mac):
            # update shapings
            old_shaping = self._machine_shapings[mac]
            old_id = old_shaping['id']
            self._unshape_interface(old_id, self.wan, old_shaping['ip'], old_shaping['tc'].up)
            self._unshape_interface(old_id, self.lan, old_shaping['ip'], old_shaping['tc'].down)
            self.idmanager.free(old_id)
            del self._machine_shapings[mac]
        self._machine_controls[mac]['is_shaping'] = False
        return TrafficControlRc(code=ReturnCode.OK)

    def _unshape_interface(self, mark, eth, ip, settings):
        """Unshape traffic for a given IP/setting on a network interface
        """
        raise NotImplementedError('Subclass should implement this')

    def _shape_interface(self, mark, eth, ip, shaping):
        """Shape traffic for a given IP
        """
        raise NotImplementedError('Subclass should implement this')

    def _update_mcontrol(self, mc):
        self.db_task.queue.put((
            (mc['mac'], mc.get('ip'), mc.get('profile_name'), mc['is_capturing'], mc['is_shaping'], mc['online'], mc["last_update_time"]),
            'add_mcontrol'))

    @address_check
    def getCapturePackets(self, mac, mc):
        self.logger.info("getCapturePackets mac:{0}".format(mac))

        pkts = self.scapy_task.getCapturePackets(mc['ip'])
        if pkts is None:
            return TrafficControlRc(
                code=ReturnCode.CAPTURE_NOT_READY,
                message="capture is not ready")

        packet_dump = PacketsToJson(pkts)
        # self.logger.info("packets: {}".format(packet_dump))

        return TrafficControlRc(
                code=ReturnCode.OK,
                message=packet_dump)

    @address_check
    def startCapture(self, mac, mc):
        self.logger.info("startCapture mac:{0}".format(mac))
        self.scapy_task.startCapture(self.lan_name, mc['ip'], mac)

        mc['is_capturing'] = True
        self._update_mcontrol(mc)

        return TrafficControlRc(code=ReturnCode.OK)

    @address_check
    def stopCapture(self, mac, mc):
        self.logger.info("stopCapture mac:{0}".format(mac))
        self.scapy_task.stopCapture(self.lan_name, mc['ip'], mac)

        mc['is_capturing'] = False
        self._update_mcontrol(mc)

        return TrafficControlRc(code=ReturnCode.OK)




