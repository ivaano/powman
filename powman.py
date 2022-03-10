import smtplib
import ssl
import subprocess
import sys
import threading
import traceback
import time
import socket
import paramiko
import yaml
import logging
from nut2 import PyNUTClient, PyNUTError
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from wakeonlan import send_magic_packet

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(asctime)s - %(message)s")

LEVEL = {
    0: 'INFO',
    1: 'WARN',
    2: 'ERROR'
}
SECONDS_PER_UNIT = {"s": 1, "m": 60, "h": 3600}
TEXT_TEMPLATE = '''{host} Administrator,
{body}
Thank You,
Powman'''
HTML_TEMPLATE = '''<html><head></head>
    <body>
        <p>{host} Administrator,</p>
        <p>{body}</p>
        <p>
            Thank You,<br />
            <b>Powman</b>
        </p>
    </body>
</html>'''
config_alerts = None


def load_config(config_file: str):
    global config_alerts
    hosts = []
    with open(config_file, 'r') as f:
        config = yaml.safe_load(f)
        if not config.get('general').get('nut_host'):
            logging.warning("nut_host shouldn't be empty")

        for host in config['hosts']:
            if 'method' and 'runtime_limit' or 'runtime_battery' in config['hosts'][host]:

                if 'port' and 'username' and 'commands' in config['hosts'][host]:

                    runtime_limit = int(config['hosts'][host]['runtime_limit']) if 'runtime_limit' in \
                                                                                   config['hosts'][host] else None
                    runtime_battery = int(
                        config['hosts'][host]['runtime_battery_charge']) if 'runtime_battery_charge' in \
                                                                            config['hosts'][host] else None

                    hosts.append(Host(
                        host=host,
                        port=config['hosts'][host]['port'],
                        method=config['hosts'][host]['method'].lower(),
                        user=config['hosts'][host]['username'],
                        password=None,
                        runtime_limit=runtime_limit,
                        runtime_battery=runtime_battery,
                        cmds=config['hosts'][host]['commands'],
                        wol_mac=config['hosts'][host]['wol_mac'],
                        private_key=config['hosts'][host]['private_rsa_key']
                    ))
                else:
                    logging.warning("Unable to load %s host's configuration! Missing 'port', 'username' and/or "
                                    "'commands' config values!", host)
            else:
                logging.warning("Unable to load %s host! Missing 'type' and/or 'runtime_limit' config values!", host)
        config['hosts'] = hosts
        config_alerts = config['general']['alerts']
        return config


def notify(level: int, notification_type: str, short_description: str, long_description: str) -> None:
    cfg_notif = config_alerts

    if not cfg_notif['triggers'][notification_type]:
        return

    # SMTP
    if cfg_notif['smtp']['enabled']:
        # Generate email content
        smtp_host = cfg_notif['smtp']['host']
        smtp_port = cfg_notif['smtp']['port']
        user = cfg_notif['smtp']['user']
        password = cfg_notif['smtp']['password']
        to_addr = cfg_notif['smtp']['to_address']
        subject = '[{}]: {}'.format(LEVEL[level], short_description)
        text_msg = TEXT_TEMPLATE.format(host=socket.gethostname(), body=long_description)
        html_msg = HTML_TEMPLATE.format(host=socket.gethostname(), body=long_description)

        try:
            smtp_msg = MIMEMultipart('alternative')
            smtp_msg['Subject'] = subject
            smtp_msg['From'] = user
            smtp_msg['To'] = to_addr
            smtp_msg.attach(MIMEText(text_msg, 'plain'))
            smtp_msg.attach(MIMEText(html_msg, 'html'))
            with smtplib.SMTP_SSL(smtp_host, smtp_port, context=ssl.create_default_context()) as smtp_server:
                smtp_server.login(user, password)
                smtp_server.sendmail(user, to_addr, smtp_msg.as_string())
        except Exception:
            logging.error("Unable to send email notification! Reason:\n%s", traceback.print_exc())


def host_check(host):
    logging.info('checking {}'.format(host.host))
    down = True
    retry_count = 0
    while down:
        if not host.is_alive():
            host.perform_wol()
        else:
            notify(0, 'host_turned_off', 'Host {} has been turned on!'.format(host.host),
                   'Host {} has been powered up.'.format(host.host))
            down = False
        time.sleep(15)

        retry_count = retry_count + 1
        if retry_count > 4:
            down = False
    logging.info('Host Check Thread exit')


class Host:
    def __init__(self, host, port, method, user, password, runtime_limit, cmds, runtime_battery=None, wol_mac=None,
                 private_key=None):
        self.host = host
        self.port = port
        self.method = method
        self.user = user
        self.password = password
        self.runtime_limit = runtime_limit
        self.runtime_battery = runtime_battery
        self.cmds = cmds
        self.turned_off = False
        self.key = private_key
        self.wol_mac = wol_mac

    def is_alive(self):
        try:
            subprocess.check_output(
                'ping -c 2 {}'.format(self.host).split(' '),
                stderr=subprocess.STDOUT
            )
            return True
        except subprocess.CalledProcessError:
            logging.warning("There is no ping response from %s host! Perhaps it is offline", self.host)

        return False

    def is_accessible(self):
        if self.method == 'ssh':
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                key = paramiko.RSAKey.from_private_key_file(self.key)
                ssh.connect(self.host, username=self.user, pkey=key)
                ssh.close()
                return True
            except Exception:
                notify(1, "host_connection_fail", "Unable to access {} host!".format(self.host),
                       "Unable to access {} host via SSH! Please check to make sure the host is reachable from the "
                       "host running HawkUPS system. Please check logs for more info.".format(self.host))
                logging.warning("Unable to access %s host via SSH! Please check to make sure the host is reachable "
                                "from the host running HawkUPS system! Reason:\n%s", self.host, traceback.print_exc())

            return False
        else:
            logging.warning("Unrecognized host type for %s", self.host)

    def perform_shutdown(self):
        if self.method == 'ssh':
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                key = paramiko.RSAKey.from_private_key_file(self.key)
                ssh.connect(self.host, username=self.user, pkey=key)
                ssh.exec_command('; '.join(self.cmds))
                ssh.close()
                self.turned_off = True
                notify(0, 'host_turned_off', 'Host {} has been turned off!'.format(self.host),
                       'Host {} has been powered down due to UPS\'s current runtime.'.format(self.host))
                logging.warning("Host %s has been powered down due to UPS\'s current runtime", self.host)
            except Exception:
                notify(1, 'host_turned_off', 'Unable to shutdown {} host!'.format(self.host),
                       'Unable to shutdown {} host due to unexpected error! Please see logs for more info.'.format(
                           self.host))
                logging.warning("Unable to shutdown %s host due to unexpected error! Reason\n%s", self.host,
                                traceback.print_exc())
        self.turned_off = True

    def perform_wol(self):
        logging.info("Sending wol packet to %s", self.host)
        send_magic_packet(self.wol_mac)
        self.turned_off = False


class UPSChecker:
    def __init__(self, config: dict):
        self.config = config
        self.interval = 3
        try:
            self.client = self.connect_client()
        except PyNUTError as e:
            logging.error("Unable to connect to nut server, %s", e)
            exit()
        self.monitor()

    def connect_client(self):
        return PyNUTClient(host=self.config.get('general').get('nut_host'),
                           port=self.config.get('general').get('nut_port'),
                           login=self.config.get('general').get('nut_login'),
                           password=self.config.get('general').get('nut_password'), debug=False,
                           timeout=30, connect=True)

    def is_ups_online(self) -> str:
        status = None
        try:
            status = self.client.get_var(self.config.get('general').get('nut_name'), 'ups.status')
        except Exception:
            logging.error("Failed retrieving ups status")
            self.client = self.connect_client()

        return status

    def monitor(self):
        ups_status_change = False
        initial_runtime = 0
        logging.info("Monitoring UPS starting")
        while True:
            status = self.is_ups_online()

            if status == 'OL' or status == 'OL CHRG':
                initial_runtime = int(
                    self.client.get_var(self.config.get('general').get('nut_name'), 'battery.runtime'))

                if ups_status_change:
                    notify(0, 'ups_status_change', 'UPS back on power grid mode!',
                           "Power has been detected from the grid. The UPS has changed back to power grid mode and "
                           "the battery will be charged whenever needed.")
                    ups_status_change = False
                    threads = list()
                    for host in self.config.get('hosts'):
                        if host.wol_mac:
                            x = threading.Thread(target=host_check, args=(host,))
                            threads.append(x)
                            x.start()

            elif status == 'OB DISCHRG':
                if not ups_status_change:
                    notify(1, 'ups_status_change', 'UPS on battery mode!',
                           "Power outage has been detected! The UPS has changed to battery mode, proceeding to watch "
                           "battery's runtime...")
                    ups_status_change = True
                current_runtime = int(
                    self.client.get_var(self.config.get('general').get('nut_name'), 'battery.runtime'))
                for host in self.config.get('hosts'):
                    if not host.turned_off:
                        if host.runtime_battery:
                            battery_charge = int(self.client.get_var(self.config.get('general').get('nut_name'),
                                                                     'battery.charge'))
                            if battery_charge < host.runtime_battery:
                                host.perform_shutdown()
                        else:
                            lapsed_runtime = initial_runtime - current_runtime
                            if lapsed_runtime > host.runtime_limit and host.is_accessible():
                                host.perform_shutdown()

            time.sleep(self.interval)


if __name__ == '__main__':
    if not len(sys.argv) > 1:
        logging.error("Missing config file path argument! Please include one.")
        exit(0)
    try:
        check = UPSChecker(load_config(sys.argv[1]))
    except FileNotFoundError:
        logging.error("Invalid config file passed.")
    except KeyboardInterrupt:
        logging.info("Exiting")
