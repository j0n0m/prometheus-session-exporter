import prometheus_client
import time
import argparse
import utmp
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileModifiedEvent
from typing import Callable
from datetime import datetime


# These defaults can be overwritten by command line arguments
SERVER_HOST = "0.0.0.0"
SERVER_PORT = 9999
FETCH_INTERVAL = 15
WATCHFILE = "/var/run/utmp"


class FileOpenedHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if not event.is_directory and isinstance(event, FileModifiedEvent) and event.src_path == WATCHFILE:
            handle_sessions_changed()


class Session:
    """ This class is used to create a Session object containing info on an SSH session, mainly for readability """

    def __init__(self, user : str, tty : str, ip_addr : str, login_time : str):
        self.user = user # Username that is logged in
        self.tty = tty # Which tty is used
        self.ip_addr = ip_addr # remote IP address
        self.login_time = login_time # time of login
        self.scraped = False # has this session been scraped by prometheus

    def __str__(self):
        return f"{self.user} from {self.ip_addr} at {datetime.fromtimestamp(self.login_time)}"

    def __repr__(self):
        return f"{self.user} {self.ip_addr} {self.tty} {self.login_time}"

    def __eq__(self, other):
        return self.user == other.user and self.tty == other.tty and self.ip_addr == other.ip_addr and self.login_time == other.login_time


def get_utmp_data() -> list[Session]:
    """
    Returns a list of Session Objects
    The function uses the utmp library. The utmp file contains information about ALL currently logged in users,
    including local users (not SSH sessions). We filter out the local users by checking if the remote IP address
    is empty and set the hostname for the local sessions to "localhost".
    """
    sessions : list[Session] = []
    with open(WATCHFILE, "rb") as fd:
        buffer = fd.read()
        for record in utmp.read(buffer):
            if record.type == utmp.UTmpRecordType.user_process:
                    sessions.append(Session(record.user, record.line, record.host or "localhost", record.sec))
    return sessions



def handle_sessions_changed() -> None:
    """ 
    This function fetches the current list of SSH sessions and compares it to the previous list of SSH sessions.
    If the number of sessions has changed, it adds or removes labelsets to the gauge_num_sessions metric.
    """
    global sessions, gauge_num_sessions

    new_sessions = get_utmp_data()

    for new_session in new_sessions:
        # Looking for newly found SSH sessions
        if not new_session in sessions:
            print(f"Session connected: {str(new_session)}")
            sessions.append(new_session)
            gauge_num_sessions.labels(user=new_session.user, tty=new_session.tty, remote_ip=new_session.ip_addr, login_time=new_session.login_time).set_function(gauge_num_sessions_func_decorator(new_session))

    for old_session in sessions:
        # Looking for SSH sessions that no longer exist
        if not old_session in new_sessions:
            # prevent losing this session between prometheus scrapes
            if old_session.scraped:
                print(f"Session disconnected and/or labelset removed: {str(old_session)}")
                sessions.remove(old_session)
                gauge_num_sessions.remove(old_session.user, old_session.tty, old_session.ip_addr, old_session.login_time)
            else:
                print(f"Session disconnected: {str(old_session)}")
                print("Waiting for next scrape before removing the labelset")



def parse_arguments() -> None:
    global FETCH_INTERVAL, SERVER_PORT, SERVER_HOST, WATCHFILE

    parser = argparse.ArgumentParser(
        prog="python prometheus-ssh-exporter.py",
        description="Prometheus exporter for info about SSH sessions")
    parser.add_argument("-H", "--host", type=str,
                        default=SERVER_HOST, help="Hostname to bind to")
    parser.add_argument("-p", "--port", type=int, default=SERVER_PORT,
                        help="Port for the server to listen to")
    parser.add_argument("-i", "--interval", type=int, default=FETCH_INTERVAL,
                        help="Interval in seconds to fetch SSH sessions data")
    parser.add_argument("-f", "--file", type=str, default=WATCHFILE,
                        help="File that changes every time a new SSH session is opened or closed")

    args = parser.parse_args()
    FETCH_INTERVAL = args.interval
    SERVER_PORT = args.port
    SERVER_HOST = args.host
    WATCHFILE = args.file

def gauge_num_sessions_func_decorator(gauge_session : Session) -> Callable[[], float]:
    def gauge_num_session_func() -> float:
        # Due to removing the labelset after a disconnect, this function should always return 1.0 or not be called.
        # everything in here is simply to play it safe
        global sessions
        # prevent losing this session between prometheus scrapes
        if not gauge_session.scraped:
            gauge_session.scraped = True
            return 1.0
        return float(gauge_session in sessions)
        
    return gauge_num_session_func


if __name__ == "__main__":
    """
    This program exports the number of SSH sessions as a metric "ssh_num_sessions" for prometheus.
    It applies labelsets to the gauge, containing the username, tty, remote IP address, and time of login.
    That way we can filter by the remote IP in Grafana, getting the number of SSH sessions by IP address,
    or sum them up to get the total number of sessions.
    """

    parse_arguments()
    
    gauge_num_sessions = prometheus_client.Gauge(
        "ssh_num_sessions", "Number of SSH sessions", ["user", "tty", "remote_ip", "login_time"])
    
    # sessions contains the current list of sessions
    sessions = get_utmp_data()

    # Initial metrics
    for initial_session in sessions:
        gauge_num_sessions.labels(user=initial_session.user, tty=initial_session.tty, remote_ip=initial_session.ip_addr, login_time=initial_session.login_time).set_function(gauge_num_sessions_func_decorator(initial_session))
        print(f"Initial connection: {str(initial_session)}")


    """
    Start the watchdog to monitor the WATCHDOG file for changes. 
    This is used to immediately look for changes in the SSH sessions when a new session is opened or closed
    to prevent missing any sessions that lasted less than the FETCH_INTERVAL.
    """
    print(f"Watching file {WATCHFILE} for changes...")
    event_handler = FileOpenedHandler()
    observer = Observer()
    observer.schedule(event_handler, path=WATCHFILE, recursive=False)
    observer.start()

    # Start up the server to expose the metrics.
    prometheus_client.start_http_server(SERVER_PORT)
    print(f"Started metrics server bound to {SERVER_HOST}:{SERVER_PORT}")

    # Generate some requests.
    print(f"Looking for SSH connection changes at interval {FETCH_INTERVAL}")
    try:

        while True:
            # Keep looking for changes in the SSH sessions in case the watchdog missed something
            handle_sessions_changed()
            time.sleep(FETCH_INTERVAL)

    except:
        print("Terminating...")
        observer.stop()
    observer.join()