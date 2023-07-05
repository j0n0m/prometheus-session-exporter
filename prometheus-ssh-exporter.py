import prometheus_client
import time
import argparse
import utmp
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileModifiedEvent
from typing import Callable, Any
from datetime import datetime


# These defaults can be overwritten by command line arguments
SERVER_HOST = "0.0.0.0"
SERVER_PORT = 9999
FETCH_INTERVAL = 15
WATCHFILE = "/var/run/utmp"

# Disable labels as you wish
# Except disabling all, that's broken right now :)
DISABLE_USER_LABEL = False
DISABLE_TTY_LABEL = False
DISABLE_REMOTE_IP_LABEL = False
DISABLE_LOGIN_TIME_LABEL = False

class FileOpenedHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if not event.is_directory and isinstance(event, FileModifiedEvent) and event.src_path == WATCHFILE:
            handle_sessions_changed()


class Session:
    """ This class is used to create a Session object containing info on a session, mainly for readability """

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
    
    def equal_labelset(self, other):
        return ((DISABLE_USER_LABEL or self.user == other.user) 
                and (DISABLE_TTY_LABEL or self.tty == other.tty) 
                and (DISABLE_REMOTE_IP_LABEL or  self.ip_addr == other.ip_addr) 
                and (DISABLE_LOGIN_TIME_LABEL or self.login_time == other.login_time))

def get_utmp_data() -> list[Session]:
    """
    Returns a list of Session Objects
    The function uses the utmp library. The utmp file contains information about ALL currently logged in users,
    including local users. We filter out the local users by checking if the remote IP address
    is empty and set the hostname for the local sessions to "localhost".
    """
    sessions : list[Session] = []
    with open(WATCHFILE, "rb") as fd:
        buffer = fd.read()
        for record in utmp.read(buffer):
            if record.type == utmp.UTmpRecordType.user_process:
                # TODO check addr0 for localhost
                sessions.append(Session(record.user, record.line, record.host or "localhost", record.sec))
    return sessions



def handle_sessions_changed() -> None:
    """ 
    This function fetches the current list of sessions and compares it to the previous list of sessions.
    If the number of sessions has changed, it adds or removes labelsets to the gauge_num_sessions metric.
    """
    global sessions, gauge_num_sessions

    new_sessions = get_utmp_data()

    for new_session in new_sessions:
        # Looking for newly found sessions
        if not new_session in sessions:
            print(f"New session detected: {str(new_session)}")
            sessions.append(new_session)
            gauge_num_sessions.labels(user=new_session.user, tty=new_session.tty, remote_ip=new_session.ip_addr, login_time=new_session.login_time).set_function(gauge_num_sessions_func_decorator(new_session))

    for old_session in sessions:
        # Looking for sessions that no longer exist
        if not old_session in new_sessions:
            print(f"Closed session detected: {str(old_session)}")
            # prevent losing this session between prometheus scrapes
            if old_session.scraped:
                sessions.remove(old_session)
                if not sum([1 for s in sessions if old_session.equal_labelset(s)]):
                    print("Removing labelset")
                    gauge_num_sessions.remove(user=old_session.user, tty=old_session.tty, remote_ip=old_session.ip_addr, login_time=old_session.login_time)
            else:
                print("Waiting for next scrape before removing the labelset")



def parse_arguments() -> None:
    global FETCH_INTERVAL, SERVER_PORT, SERVER_HOST, WATCHFILE

    parser = argparse.ArgumentParser(
        prog="python prometheus-ssh-exporter.py",
        description="Prometheus exporter for info about sessions")
    parser.add_argument("-H", "--host", type=str,
                        default=SERVER_HOST, help="Hostname to bind to")
    parser.add_argument("-p", "--port", type=int, default=SERVER_PORT,
                        help="Port for the server to listen to")
    parser.add_argument("-i", "--interval", type=int, default=FETCH_INTERVAL,
                        help="Interval in seconds to fetch sessions data")
    parser.add_argument("-f", "--file", type=str, default=WATCHFILE,
                        help="File that changes every time a new session is opened or closed")

    args = parser.parse_args()
    FETCH_INTERVAL = args.interval
    SERVER_PORT = args.port
    SERVER_HOST = args.host
    WATCHFILE = args.file

def gauge_num_sessions_func_decorator(gauge_session : Session) -> Callable[[], float]:
    def gauge_num_session_func() -> float:
        global sessions
        # prevent losing this session between prometheus scrapes
        gauge = 0.0
        for session in sessions:
            if gauge_session.equal_labelset(session):
                session.scraped = True
                gauge += 1.0
        return gauge
        
    return gauge_num_session_func


class RobustGauge(prometheus_client.Gauge):
    # if kwargs are used superfluous labels will be ignored
    def labels(self : prometheus_client.Gauge, *labelvalues : Any, **labelkwargs : Any):
        if not self._labelnames:
            raise ValueError('No label names were set when constructing %s' % self)

        if self._labelvalues:
            raise ValueError('{} already has labels set ({}); can not chain calls to .labels()'.format(
                self,
                dict(zip(self._labelnames, self._labelvalues))
            ))

        if labelvalues and labelkwargs:
            raise ValueError("Can't pass both *args and **kwargs")

        if labelkwargs:
            for l in self._labelnames:
                if not l in labelkwargs:
                    raise ValueError('Missing label name: {}'.format(l))
            labelvalues = tuple(str(labelkwargs[l]) for l in self._labelnames)
        else:
            if len(labelvalues) != len(self._labelnames):
                raise ValueError('Incorrect label count')
            labelvalues = tuple(str(l) for l in labelvalues)
        with self._lock:
            if labelvalues not in self._metrics:
                self._metrics[labelvalues] = self.__class__(
                    self._name,
                    documentation=self._documentation,
                    labelnames=self._labelnames,
                    unit=self._unit,
                    _labelvalues=labelvalues,
                    **self._kwargs
                )
            return self._metrics[labelvalues]
        
    def remove(self, *labelvalues: Any, **labelkwargs : Any) -> None:
        if not self._labelnames:
            raise ValueError('No label names were set when constructing %s' % self)
        
        if labelvalues and labelkwargs:
            raise ValueError("Can't pass both *args and **kwargs")

        if labelkwargs:
            for l in self._labelnames:
                if not l in labelkwargs:
                    raise ValueError('Missing label name: {}'.format(l))
            labelvalues = tuple(str(labelkwargs[l]) for l in self._labelnames)
        else:
            if len(labelvalues) != len(self._labelnames):
                raise ValueError('Incorrect label count (expected %d, got %s)' % (len(self._labelnames), labelvalues))
            labelvalues = tuple(str(l) for l in labelvalues)

        """Remove the given labelset from the metric."""
        with self._lock:
            del self._metrics[labelvalues]


if __name__ == "__main__":
    """
    This program exports the number of sessions as a metric "num_sessions" for prometheus.
    It applies labelsets to the gauge, containing the username, tty, remote IP address, and time of login.
    That way we can filter by the remote IP in Grafana, getting the number of sessions by IP address,
    or sum them up to get the total number of sessions.
    """

    parse_arguments()

    labels = ["user", "tty", "remote_ip", "login_time"]
    if DISABLE_USER_LABEL:
        labels.remove("user")
    if DISABLE_TTY_LABEL:
        labels.remove("tty")
    if DISABLE_REMOTE_IP_LABEL:
        labels.remove("remote_ip")
    if DISABLE_LOGIN_TIME_LABEL:
        labels.remove("login_time")
    
    gauge_num_sessions = RobustGauge(
        "num_sessions", "Number of sessions", labels)
    
    # sessions contains the current list of sessions
    sessions = get_utmp_data()

    # Initial metrics
    for initial_session in sessions:
        print(f"Initial connection: {str(initial_session)}")
        gauge_num_sessions.labels(user=initial_session.user, tty=initial_session.tty, remote_ip=initial_session.ip_addr, login_time=initial_session.login_time).set_function(gauge_num_sessions_func_decorator(initial_session))


    """
    Start the watchdog to monitor the WATCHDOG file for changes. 
    This is used to immediately look for changes in the sessions when a new session is opened or closed
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
    print(f"Looking for connection changes at interval {FETCH_INTERVAL}")
    try:

        while True:
            # Keep looking for changes in the sessions in case the watchdog missed something
            handle_sessions_changed()
            time.sleep(FETCH_INTERVAL)

    except:
        print("Terminating...")
        observer.stop()
    observer.join()