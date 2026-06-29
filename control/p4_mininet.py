#!/usr/bin/env python3
"""Mininet helpers for running a BMv2 simple_switch as a Mininet node.

Adapted (original code) from the well-known p4lang/tutorials P4Switch pattern.
A P4Switch launches the user-space `simple_switch` process and attaches each
Mininet veth interface to it via `-i <port>@<intf>`. Thrift runtime port is
exposed so the controller can populate tables and read registers/counters.
"""
import os
import tempfile
import socket
from time import sleep

from mininet.node import Switch, Host
from mininet.log import info, error, debug
from mininet.moduledeps import pathCheck

SWITCH_START_TIMEOUT = 10  # seconds


class P4Host(Host):
    """A Mininet host with offloading disabled so Scapy sees raw frames."""

    def config(self, **params):
        r = super(P4Host, self).config(**params)
        # Disable NIC offloads: checksums must be computed on the wire so the
        # BMv2 switch and Scapy attackers see correct packets.
        for off in ["rx", "tx", "sg"]:
            cmd = "/sbin/ethtool --offload %s-eth0 %s off" % (self.name, off)
            self.cmd(cmd)
        # Single default route via eth0.
        self.cmd("ip route add default dev %s-eth0" % self.name)
        # Disable IPv6 to keep captures clean.
        self.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
        self.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
        return r

    def describe(self):
        print("**********")
        print(self.name)
        print("default interface: %s\t%s\t%s" % (
            self.defaultIntf().name,
            self.defaultIntf().IP(),
            self.defaultIntf().MAC()))
        print("**********")


class P4Switch(Switch):
    """BMv2 simple_switch as a Mininet switch node."""

    device_id = 0

    def __init__(self, name, sw_path="simple_switch", json_path=None,
                 thrift_port=None, pcap_dump=False, log_console=False,
                 log_file=None, device_id=None, **kwargs):
        Switch.__init__(self, name, **kwargs)
        assert sw_path
        assert json_path
        self.sw_path = sw_path
        self.json_path = json_path
        self.thrift_port = thrift_port
        self.pcap_dump = pcap_dump
        self.log_console = log_console
        self.log_file = log_file or ("/tmp/%s.log" % name)
        if device_id is not None:
            self.device_id = device_id
            P4Switch.device_id = max(P4Switch.device_id, device_id)
        else:
            self.device_id = P4Switch.device_id
            P4Switch.device_id += 1
        self.nanomsg = "ipc:///tmp/bm-%d-log.ipc" % self.device_id

    @classmethod
    def setup(cls):
        pass

    def check_switch_started(self, pid):
        """Wait until the Thrift port is accepting connections."""
        for _ in range(SWITCH_START_TIMEOUT * 4):
            if not os.path.exists("/proc/%d" % pid):
                return False
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex(("127.0.0.1", self.thrift_port))
            sock.close()
            if result == 0:
                return True
            sleep(0.25)
        return False

    def start(self, controllers):
        info("Starting P4 switch %s.\n" % self.name)
        args = [self.sw_path]
        for port, intf in self.intfs.items():
            if not intf.IP():
                args.extend(["-i", "%d@%s" % (port, intf.name)])
        if self.pcap_dump:
            args.append("--pcap")
        if self.thrift_port:
            args.extend(["--thrift-port", str(self.thrift_port)])
        if self.nanomsg:
            args.extend(["--nanolog", self.nanomsg])
        args.extend(["--device-id", str(self.device_id)])
        P4Switch.device_id += 1
        args.append(self.json_path)
        if self.log_console:
            args.append("--log-console")
        logfile = self.log_file
        info(" ".join(args) + "\n")

        pid = None
        with tempfile.NamedTemporaryFile() as f:
            self.cmd(" ".join(args) + " >" + logfile + " 2>&1 & echo $! >> " + f.name)
            pid = int(f.read())
        debug("P4 switch %s PID is %d.\n" % (self.name, pid))
        if not self.check_switch_started(pid):
            error("P4 switch %s did not start correctly.\n" % self.name)
            error("Check log: %s\n" % logfile)
            os._exit(1)
        info("P4 switch %s has been started.\n" % self.name)

    def stop(self):
        self.cmd("kill %" + self.sw_path)
        self.cmd("wait")
        self.deleteIntfs()

    def attach(self, intf):
        pass

    def detach(self, intf):
        pass
