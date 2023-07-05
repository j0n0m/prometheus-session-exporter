# prometheus-session-exporter
A Prometheus exporter for monitoring sessions (incl. SSH connections)

This project is largely based on [flor0's ssh exporter](https://github.com/flor0/prometheus-ssh-exporter).
However, I didn't find the name actually fits and it's not robust enough.

## Installation
Simply use the script. I plan to provide a barebones systemd service in the future.

Other than the original project, I do not recommend using docker, unless you really know what you are doing, due to an increased risk of exposing the service.
This might not seem like a big deal, but the exporters ability to export sessions happening between prometheus scrapes relies on only being used by prometheus.

### Configuration
The command line arguments are explained if you use `python3 ./prometheus-session-exporter.py --help`

A few more options are not available through the command line and have to be edited in the code. They should be easily recognisable and at the beginning.

## Configuring Prometheus

To have prometheus collect our new metrics, we need to add our server to the prometheus.yml file.
To do that open the /etc/prometheus/prometheus.yml file in an editor and add the lines
```
- job_name: sessions
    static_configs:
      - targets: ['localhost:<external port>']
```
Make sure it's indented correctly!

## Usage

You can go to your prometheus dashboard in the web browser and query num_sessions.
If everything is set up correctly you should get the metrics.
