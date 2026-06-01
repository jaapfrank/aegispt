#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import hmac
import os
import socketserver
import sys
from typing import Callable

DEFAULT_SEED = "aegispt-local-lab-suite-default-seed"


def flag_seed() -> str:
    return os.environ.get("AEGISPT_LAB_FLAG_SEED", DEFAULT_SEED)


def expected_flag(challenge_id: str) -> str:
    digest = hmac.new(
        flag_seed().encode("utf-8"),
        challenge_id.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()[:32]
    return f"aegispt{{{challenge_id}:{digest}}}"


def mqtt_diag_token() -> str:
    return hmac.new(flag_seed().encode("utf-8"), b"mqtt-diag-token", hashlib.sha256).hexdigest()[:16]


class LabTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class LineProtocolHandler(socketserver.StreamRequestHandler):
    role = "unknown"

    def write_line(self, text: str) -> None:
        self.wfile.write((text + "\n").encode("utf-8"))
        self.wfile.flush()

    def read_command(self) -> str | None:
        raw = self.rfile.readline(4096)
        if not raw:
            return None
        return raw.decode("utf-8", errors="replace").strip()


class PrinterHandler(LineProtocolHandler):
    role = "printer"

    def handle(self) -> None:
        self.write_line("AegisPrinter JetDirect 9100 ready; try HELP")
        while command := self.read_command():
            upper = command.upper()
            if upper == "HELP":
                self.write_line("COMMANDS INFO STATUS PJL")
            elif upper == "INFO":
                self.write_line("MODEL=Aegis Laser 4200; SERIAL=PRN-4421; mgmt=PJL")
            elif upper == "STATUS":
                self.write_line("READY; last_job=quarterly-payroll; storage=/flash/job-cache/")
            elif upper == 'PJL INFO ID':
                self.write_line("ID=Aegis Laser 4200; default_pin=0420")
            elif upper == 'PJL FSQUERY NAME="/FLASH/"':
                self.write_line('FILE="/flash/job-cache/flag.txt"; ACL=pin-protected')
            elif upper == 'PJL FSUPLOAD NAME="/FLASH/JOB-CACHE/FLAG.TXT" PIN=0420':
                self.write_line(expected_flag("lan-printer-pjl-job-leak"))
            else:
                self.write_line("ERR unknown_or_denied")


class NasHandler(LineProtocolHandler):
    role = "nas"

    def handle(self) -> None:
        authed = False
        self.write_line("AegisNAS SMB-LITE ready; say HELLO")
        while command := self.read_command():
            parts = command.split()
            upper = command.upper()
            if upper == "HELLO":
                self.write_line("SHARES public backups")
            elif upper == "LIST PUBLIC":
                self.write_line("FILES readme.txt backup-index.txt")
            elif upper == "GET PUBLIC BACKUP-INDEX.TXT":
                self.write_line("backup=nightly-2026 service_account=backup-reader")
            elif len(parts) == 3 and parts[0].upper() == "AUTH":
                authed = parts[1] == "backup-reader" and parts[2] == "nightly-2026"
                self.write_line("OK session=backup-reader" if authed else "ERR bad_credentials")
            elif upper == "LIST BACKUPS":
                self.write_line("FILES finance.tar.enc restore-token.txt" if authed else "ERR auth_required")
            elif upper == "GET BACKUPS RESTORE-TOKEN.TXT":
                self.write_line(expected_flag("lan-nas-backup-share-leak") if authed else "ERR auth_required")
            else:
                self.write_line("ERR unknown")


class DirectoryHandler(LineProtocolHandler):
    role = "directory"

    def handle(self) -> None:
        bound = False
        self.write_line("AegisDirectory LDAP-LITE ready")
        while command := self.read_command():
            upper = command.upper()
            if upper == "ROOTDSE":
                self.write_line("namingContext=dc=lab,dc=local; bind_hint=svc-audit")
            elif upper == "BIND SVC-AUDIT AUDIT-READONLY":
                bound = True
                self.write_line("OK bound=svc-audit")
            elif not bound:
                self.write_line("ERR bind_required")
            elif upper == "SEARCH UID=A.ANALYST":
                self.write_line("dn=uid=a.analyst; memberOf=cn=Helpdesk")
            elif upper == "SEARCH CN=HELPDESK":
                self.write_line("dn=cn=Helpdesk; nested=cn=Domain Backup Readers")
            elif upper == "SEARCH CN=DOMAIN BACKUP READERS":
                self.write_line("dn=cn=Domain Backup Readers; reset_token=BR-2026")
            elif upper == "RESET CN=BACKUP-AGENT BR-2026":
                self.write_line(expected_flag("lan-ldap-nested-group-reset"))
            else:
                self.write_line("ERR no_such_object")


class OtHandler(LineProtocolHandler):
    role = "ot"

    def handle(self) -> None:
        maintenance = False
        self.write_line("AegisPLC MODBUS-LITE ready")
        while command := self.read_command():
            upper = command.upper()
            if upper == "READ 0":
                self.write_line("REG0 device=AegisPump station=3")
            elif upper == "READ 10":
                self.write_line(f"REG10 maintenance={int(maintenance)}")
            elif upper == "WRITE 10 1":
                maintenance = True
                self.write_line("OK maintenance=1")
            elif upper == "READ 42":
                self.write_line(expected_flag("lan-ot-maintenance-register") if maintenance else "ERR maintenance_required")
            else:
                self.write_line("ERR illegal_function")


class MqttHandler(LineProtocolHandler):
    role = "mqtt"

    def handle(self) -> None:
        connected = False
        diag_ran = False
        token = mqtt_diag_token()
        self.write_line("AegisMQTT MQTT-LITE ready")
        while command := self.read_command():
            parts = command.split(maxsplit=2)
            upper = command.upper()
            if upper.startswith("CONNECT "):
                connected = True
                self.write_line("CONNACK retained_topics=$SYS/lab/diag")
            elif not connected:
                self.write_line("ERR connect_required")
            elif upper == "SUBSCRIBE $SYS/#":
                self.write_line(f"RETAINED $SYS/lab/diag token={token} topic=lab/diag/run")
            elif len(parts) == 3 and parts[0].upper() == "PUBLISH" and parts[1] == "lab/diag/run":
                diag_ran = f"token={token}" in parts[2] and "action=dump" in parts[2]
                self.write_line("PUBACK" if diag_ran else "ERR bad_diag_token")
            elif upper == "SUBSCRIBE LAB/DIAG/RESULT":
                self.write_line(
                    f"RETAINED lab/diag/result {expected_flag('lan-mqtt-retained-diagnostic')}"
                    if diag_ran
                    else "RETAINED lab/diag/result pending"
                )
            else:
                self.write_line("ERR unknown")


class DnsHandler(LineProtocolHandler):
    role = "dns"

    def handle(self) -> None:
        token = hmac.new(flag_seed().encode("utf-8"), b"dns-transfer-token", hashlib.sha256).hexdigest()[:10]
        self.write_line("AegisDNS DNS-LITE ready")
        while command := self.read_command():
            upper = command.upper()
            if upper == "QUERY NS LAB.LOCAL":
                self.write_line("NS ns1.lab.local; ns2.lab.local")
            elif upper == "QUERY TXT _TRANSFER.LAB.LOCAL":
                self.write_line(f"TXT transfer-token={token}")
            elif upper == f"AXFR LAB.LOCAL TSIG={token}".upper():
                self.write_line(f"ZONE admin.lab.local A 10.10.10.5; TXT {expected_flag('lan-dns-zone-transfer-leak')}")
            else:
                self.write_line("ERR refused")


class RedisHandler(LineProtocolHandler):
    role = "redis"

    def __init__(self, *args: object, **kwargs: object) -> None:
        self.approved = False
        super().__init__(*args, **kwargs)

    def handle(self) -> None:
        self.write_line("AegisRedis REDIS-LITE ready")
        while command := self.read_command():
            upper = command.upper()
            if upper == "PING":
                self.write_line("PONG")
            elif upper == "INFO":
                self.write_line("redis_version:lab; queue=deploy:jobs")
            elif upper == "LRANGE DEPLOY:JOBS 0 -1":
                self.write_line("1) job:42 service=artifact-signer")
            elif upper == "GET DEPLOY:JOB:42":
                self.write_line("command=sign-artifact requires approve_key=blue")
            elif upper == "SET DEPLOY:JOB:42:APPROVED BLUE":
                self.approved = True
                self.write_line("OK")
            elif upper == "GET DEPLOY:ARTIFACT:FLAG":
                self.write_line(expected_flag("lan-redis-queue-secret") if self.approved else "ERR approval_required")
            else:
                self.write_line("ERR unknown")


class MailHandler(LineProtocolHandler):
    role = "mail"

    def handle(self) -> None:
        authed = False
        self.write_line("+OK AegisMail POP3-LITE ready")
        while command := self.read_command():
            upper = command.upper()
            if upper == "USER AUDITOR":
                self.write_line("+OK user")
            elif upper == "PASS GUEST":
                authed = True
                self.write_line("+OK mailbox locked")
            elif not authed:
                self.write_line("-ERR auth required")
            elif upper == "LIST":
                self.write_line("+OK 2 messages; 1 welcome; 2 reset-code")
            elif upper == "RETR 2":
                self.write_line("+OK reset-code=MAIL-7788 target=breakglass")
            elif upper == "RESET ADMIN MAIL-7788":
                self.write_line(expected_flag("lan-mail-reset-code-takeover"))
            else:
                self.write_line("-ERR unknown")


class GitHandler(LineProtocolHandler):
    role = "git"

    def handle(self) -> None:
        cloned = False
        self.write_line("AegisGit GIT-LITE ready")
        while command := self.read_command():
            upper = command.upper()
            if upper == "CAPABILITIES":
                self.write_line("list clone log show")
            elif upper == "LIST":
                self.write_line("repos app.git infra.git")
            elif upper == "CLONE APP.GIT":
                cloned = True
                self.write_line("OK cloned app.git")
            elif upper == "LOG APP.GIT" and cloned:
                self.write_line("commits c0ffee init; deadbee remove-secret")
            elif upper == "SHOW APP.GIT DEADBEE:CONFIG" and cloned:
                self.write_line(f"DB_URL=postgres://app; OLD_SECRET={expected_flag('lan-git-history-secret')}")
            else:
                self.write_line("ERR unknown_or_not_cloned")


class KubeletHandler(LineProtocolHandler):
    role = "kubelet"

    def handle(self) -> None:
        issued_token = ""
        self.write_line("AegisKubelet KUBELET-LITE ready")
        while command := self.read_command():
            upper = command.upper()
            if upper == "STATS":
                self.write_line("pods=2 anonymous_read=true")
            elif upper == "PODS":
                self.write_line("default/api kube-system/backup-controller")
            elif upper == "TOKEN DEFAULT/API":
                issued_token = hmac.new(flag_seed().encode("utf-8"), b"kubelet-default-api", hashlib.sha256).hexdigest()[:12]
                self.write_line(f"token={issued_token}")
            elif upper == f"GETSECRET KUBE-SYSTEM/BACKUP TOKEN={issued_token}".upper() and issued_token:
                self.write_line(expected_flag("lan-kubelet-pod-secret"))
            else:
                self.write_line("ERR forbidden")


HANDLERS: dict[str, type[LineProtocolHandler]] = {
    "dns": DnsHandler,
    "directory": DirectoryHandler,
    "git": GitHandler,
    "kubelet": KubeletHandler,
    "mail": MailHandler,
    "mqtt": MqttHandler,
    "nas": NasHandler,
    "ot": OtHandler,
    "printer": PrinterHandler,
    "redis": RedisHandler,
}

DEFAULT_PORTS = {
    "dns": 5353,
    "directory": 1389,
    "git": 9418,
    "kubelet": 10250,
    "mail": 1100,
    "mqtt": 1883,
    "nas": 4450,
    "ot": 1502,
    "printer": 9100,
    "redis": 6379,
}


def make_server(role: str, host: str, port: int) -> LabTCPServer:
    handler = HANDLERS[role]
    return LabTCPServer((host, port), handler)


def run(role: str, *, host: str, port: int, server_factory: Callable[[str, str, int], LabTCPServer] = make_server) -> None:
    server = server_factory(role, host, port)
    print(f"AegisPT {role} lab service listening on {host}:{port}", flush=True)
    server.serve_forever()


def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] not in HANDLERS:
        roles = ", ".join(sorted(HANDLERS))
        print(f"usage: network_services.py <{roles}> [host] [port]", file=sys.stderr)
        return 2
    role = sys.argv[1]
    host = sys.argv[2] if len(sys.argv) > 2 else os.environ.get("AEGISPT_LAB_HOST", "0.0.0.0")
    port = int(sys.argv[3] if len(sys.argv) > 3 else os.environ.get("AEGISPT_LAB_PORT", DEFAULT_PORTS[role]))
    run(role, host=host, port=port)
    return 0


if __name__ == "__main__":
    sys.exit(main())
