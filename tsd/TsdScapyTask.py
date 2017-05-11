import threading
import time

from scapy.all import *

from sparts.sparts import option
from sparts.tasks.queue import QueueTask

from traffic_shark_thrift import TrafficSharkService

class TsdScapyStopPacket(Packet):
    name = "TsdScapyStopPacket"
    fields_desc = [IntField("tsd", 0)]

class TsdScapyTask(QueueTask):
    OPT_PREFIX = 'scapy'
    workers = 10
    max_ip_pkts_count = 1000
    pop_ip_pkts_count = 10

    def initTask(self):
        super(TsdScapyTask, self).initTask()

        bind_layers(UDP, TsdScapyStopPacket, dport=3232)
        bind_layers(UDP, TsdScapyStopPacket, sport=3232)

        self.lock = threading.Lock()
        self.ip_pkts = {}
        self.capturing_ips = []

    def stop(self):
        if self.iface:
            # self.logger.info(self.ip_pkts)
            for ip in self.ip_pkts:
                self.stopCapture(self.iface, ip, None)

    def setupIface(self, iface):
        self.iface = iface

    def startCapture(self, iface, capture_filter, ip, mac):
        filter_str = "host " + ip
        if capture_filter is not None and capture_filter != "":
            filter_str = "(host " + ip + " and " + capture_filter + ")"
        filter_str = "(udp and port 3232 and host " + ip + ") or " + filter_str

        self.logger.info('Capture start with filter:{0}'.format(filter_str))
        sniff(iface=iface, filter=filter_str, count=0, timeout=0)
        self.queue.put((iface, filter_str , ip, mac))

    def stopCapture(self, iface, ip, mac):
        stop_packet = Ether(dst=mac)/IP(dst=ip)/UDP(dport=3232,sport=3232)/TsdScapyStopPacket(tsd=3232)
        sendp(stop_packet, iface=iface)

        if mac is not None:
            with self.lock:
                if self.ip_pkts.get(ip) is not None:
                    del self.ip_pkts[ip]

    def getCapturePackets(self, ip):
        with self.lock:
            if self.ip_pkts.get(ip) is None:
                return None
            else:
                return list(self.ip_pkts[ip])

    def execute(self, item, context):
        try:
            sniff_iface, sniff_filter, sniff_ip, sniff_mac = item
        except ValueError:
            self.logger.exception('Error executing on item: {0}'.format(item))
            return

        self.logger.info('Capture start {0}'.format(item))

        with self.lock:
            self.ip_pkts[sniff_ip] = []

        thread_pkts_queue = []
        def internal_capture_pkts():
            for idx in range(len(thread_pkts_queue)):       
                if self._capture_pkt_callback(sniff_ip, thread_pkts_queue[0]):
                    thread_pkts_queue.pop(0)

        def internal_prn(raw_pkt):
            if raw_pkt.haslayer(TsdScapyStopPacket) and raw_pkt[TsdScapyStopPacket].tsd == 3232:
                return
            now = int(round(time.time() * 1000))
            # pkt = {
            #     'time': now,
            #     'raw_pkt': raw_pkt
            # }
            thread_pkts_queue.append(raw_pkt)
            internal_capture_pkts()

        def internal_stop(pkt):
            if pkt.haslayer(TsdScapyStopPacket) and pkt[TsdScapyStopPacket].tsd == 3232:
                self.logger.info('Capture stopped for ip:{0} mac:{1}'.format(sniff_ip, sniff_mac))
                return True
            return False

        try:
            sniff(iface=sniff_iface, filter=sniff_filter, prn=internal_prn, stop_filter=internal_stop)
        except:
            self.logger.exception(
                'unable to run sniff: {0}'.format(item)
            )
            raise

    def _capture_pkt_callback(self, ip, pkt):
        if self.lock.acquire(False):
            # pkt.show()
            if self.ip_pkts.get(ip) is not None:
                self.ip_pkts[ip].append(pkt)
                if len(self.ip_pkts[ip]) > self.max_ip_pkts_count:
                    for i in range(0, self.pop_ip_pkts_count):
                        self.ip_pkts[ip].pop(0)
            self.lock.release()
            return True
        return False

