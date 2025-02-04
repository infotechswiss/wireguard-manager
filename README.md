![](https://github.com/swissmakers/wireguard-manager/workflows/wireguard-manager%20build%20release/badge.svg)

# wireguard-manager

A web interface to manage WireGuard.

## Features

- User-Friendly UI
- Authentication
- Manage extra client information (name, email, etc.)
- Retrieve client config using QR code / file / email / Telegram

![wireguard-manager 0.3.7](https://user-images.githubusercontent.com/37958026/177041280-e3e7ca16-d4cf-4e95-9920-68af15e780dd.png)

## Run WireGuard-UI

> ⚠️The default username and password are `admin`. Please change it to secure your setup.

### Using binary file

Download the binary file from the release page and run it directly on the host machine

```
./wireguard-manager
```

### Using docker compose

The [examples/docker-compose](examples/docker-compose) folder contains example docker-compose files.
Choose the example which fits you the most, adjust the configuration for your needs, then run it like below:

```
docker-compose up
```

## Environment Variables

| Variable                      | Description                                                                                                                                                                                                                                                                         | Default                            |
|-------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------|
| `BASE_PATH`                   | Set this variable if you run wireguard-manager under a subpath of your reverse proxy virtual host (e.g. /wireguard)                                                                                                                                                                      | N/A                                |
| `PROXY`                       | Use X-FORWARDED-FOR header for logging                                                                                                                                                    | `false`    
| `BIND_ADDRESS`                | The addresses that can access to the web interface and the port, use unix:///abspath/to/file.socket for unix domain socket.                                                                                                                                                         | 0.0.0.0:80                         |
| `SESSION_SECRET`              | The secret key used to encrypt the session cookies. Set this to a random value                                                                                                                                                                                                      | N/A                                |
| `SESSION_SECRET_FILE`         | Optional filepath for the secret key used to encrypt the session cookies. Leave `SESSION_SECRET` blank to take effect                                                                                                                                                               | N/A                                |
| `SESSION_MAX_DURATION`        | Max time in days a remembered session is refreshed and valid. Non-refreshed session is valid for 7 days max, regardless of this setting.                                                                                                                                            | 90                                 |
| `SUBNET_RANGES`               | The list of address subdivision ranges. Format: `SR Name:10.0.1.0/24; SR2:10.0.2.0/24,10.0.3.0/24` Each CIDR must be inside one of the server interfaces.                                                                                                                           | N/A                                |
| `WGM_USERNAME`               | The username for the login page. Used for db initialization only                                                                                                                                                                                                                    | `admin`                            |
| `WGM_PASSWORD`               | The password for the user on the login page. Will be hashed automatically. Used for db initialization only                                                                                                                                                                          | `admin`                            |
| `WGM_PASSWORD_FILE`          | Optional filepath for the user login password. Will be hashed automatically. Used for db initialization only. Leave `WGM_PASSWORD` blank to take effect                                                                                                                            | N/A                                |
| `WGM_PASSWORD_HASH`          | The password hash for the user on the login page. (alternative to `WGM_PASSWORD`). Used for db initialization only                                                                                                                                                                 | N/A                                |
| `WGM_PASSWORD_HASH_FILE`     | Optional filepath for the user login password hash. (alternative to `WGM_PASSWORD_FILE`). Used for db initialization only. Leave `WGM_PASSWORD_HASH` blank to take effect                                                                                                         | N/A                                |
| `WGM_ENDPOINT_ADDRESS`       | The default endpoint address used in global settings where clients should connect to. The endpoint can contain a port as well, useful when you are listening internally on the `WGM_SERVER_LISTEN_PORT` port, but you forward on another port (ex 9000). Ex: myvpn.dyndns.com:9000 | Resolved to your public ip address |
| `WGM_FAVICON_FILE_PATH`      | The file path used as website favicon                                                                                                                                                                                                                                               | Embedded WireGuard logo            |
| `WGM_DNS`                    | The default DNS servers (comma-separated-list) used in the global settings                                                                                                                                                                                                          | `1.1.1.1`                          |
| `WGM_MTU`                    | The default MTU used in global settings                                                                                                                                                                                                                                             | `1450`                             |
| `WGM_PERSISTENT_KEEPALIVE`   | The default persistent keepalive for WireGuard in global settings                                                                                                                                                                                                                   | `15`                               |
| `WGM_FIREWALL_MARK`          | The default WireGuard firewall mark                                                                                                                                                                                                                                                 | `0xca6c`  (51820)                  |
| `WGM_TABLE`                  | The default WireGuard table value settings                                                                                                                                                                                                                                          | `auto`                             |
| `WGM_CONFIG_FILE_PATH`       | The default WireGuard config file path used in global settings                                                                                                                                                                                                                      | `/etc/wireguard/wg0.conf`          |
| `WGM_LOG_LEVEL`              | The default log level. Possible values: `DEBUG`, `INFO`, `WARN`, `ERROR`, `OFF`                                                                                                                                                                                                     | `INFO`                             |
| `WG_CONF_TEMPLATE`            | The custom `wg.conf` config file template. Please refer to our [default template](https://github.com/swissmakers/wireguard-manager/blob/master/templates/wg.conf)                                                                                                                        | N/A                                |
| `EMAIL_FROM_ADDRESS`          | The sender email address                                                                                                                                                                                                                                                            | N/A                                |
| `EMAIL_FROM_NAME`             | The sender name                                                                                                                                                                                                                                                                     | `WireGuard Manager`                     |
| `SENDGRID_API_KEY`            | The SendGrid api key                                                                                                                                                                                                                                                                | N/A                                |
| `SENDGRID_API_KEY_FILE`       | Optional filepath for the SendGrid api key. Leave `SENDGRID_API_KEY` blank to take effect                                                                                                                                                                                           | N/A                                |
| `SMTP_HOSTNAME`               | The SMTP IP address or hostname                                                                                                                                                                                                                                                     | `127.0.0.1`                        |
| `SMTP_PORT`                   | The SMTP port                                                                                                                                                                                                                                                                       | `25`                               |
| `SMTP_USERNAME`               | The SMTP username                                                                                                                                                                                                                                                                   | N/A                                |
| `SMTP_PASSWORD`               | The SMTP user password                                                                                                                                                                                                                                                              | N/A                                |
| `SMTP_PASSWORD_FILE`          | Optional filepath for the SMTP user password. Leave `SMTP_PASSWORD` blank to take effect                                                                                                                                                                                            | N/A                                |
| `SMTP_AUTH_TYPE`              | The SMTP authentication type. Possible values: `PLAIN`, `LOGIN`, `NONE`                                                                                                                                                                                                             | `NONE`                             |
| `SMTP_ENCRYPTION`             | The encryption method. Possible values: `NONE`, `SSL`, `SSLTLS`, `TLS`, `STARTTLS`                                                                                                                                                                                                  | `STARTTLS`                         |
| `SMTP_HELO`                   | Hostname to use for the HELO message. smtp-relay.gmail.com needs this set to anything but `localhost`                                                                                                                                                                               | `localhost`                        |
| `TELEGRAM_TOKEN`              | Telegram bot token for distributing configs to clients                                                                                                                                                                                                                              | N/A                                |
| `TELEGRAM_ALLOW_CONF_REQUEST` | Allow users to get configs from the bot by sending a message                                                                                                                                                                                                                        | `false`                            |
| `TELEGRAM_FLOOD_WAIT`         | Time in minutes before the next conf request is processed                                                                                                                                                                                                                           | `60`                               |

### Defaults for server configuration

These environment variables are used to control the default server settings used when initializing the database.

| Variable                          | Description                                                                                   | Default         |
|-----------------------------------|-----------------------------------------------------------------------------------------------|-----------------|
| `WGM_SERVER_INTERFACE_ADDRESSES` | The default interface addresses (comma-separated-list) for the WireGuard server configuration | `10.252.1.0/24` |
| `WGM_SERVER_LISTEN_PORT`         | The default server listen port                                                                | `51820`         |
| `WGM_SERVER_POST_UP_SCRIPT`      | The default server post-up script                                                             | N/A             |
| `WGM_SERVER_POST_DOWN_SCRIPT`    | The default server post-down script                                                           | N/A             |

### Defaults for new clients

These environment variables are used to set the defaults used in `New Client` dialog.

| Variable                                    | Description                                                                                     | Default     |
|---------------------------------------------|-------------------------------------------------------------------------------------------------|-------------|
| `WGM_DEFAULT_CLIENT_ALLOWED_IPS`           | Comma-separated-list of CIDRs for the `Allowed IPs` field. (default )                           | `0.0.0.0/0` |
| `WGM_DEFAULT_CLIENT_EXTRA_ALLOWED_IPS`     | Comma-separated-list of CIDRs for the `Extra Allowed IPs` field. (default empty)                | N/A         |
| `WGM_DEFAULT_CLIENT_USE_SERVER_DNS`        | Boolean value [`0`, `f`, `F`, `false`, `False`, `FALSE`, `1`, `t`, `T`, `true`, `True`, `TRUE`] | `true`      |
| `WGM_DEFAULT_CLIENT_ENABLE_AFTER_CREATION` | Boolean value [`0`, `f`, `F`, `false`, `False`, `FALSE`, `1`, `t`, `T`, `true`, `True`, `TRUE`] | `true`      |

### Docker only

These environment variables only apply to the docker container.

| Variable              | Description                                                   | Default |
|-----------------------|---------------------------------------------------------------|---------|
| `WGM_MANAGE_START`   | Start/stop WireGuard when the container is started/stopped    | `false` |
| `WGM_MANAGE_RESTART` | Auto restart WireGuard when we Apply Config changes in the UI | `false` |
| `WGM_MANAGE_RELOAD`  | Auto reload WireGuard when we Apply Config changes in the UI  | `false` |

## Auto restart WireGuard daemon

WireGuard-UI only takes care of configuration generation. You can use systemd to watch for the changes and restart the
service. Following is an example:

### Using systemd

#### Create dedicated wireguard-manager user
```bash
useradd -m -r -s /bin/false -d /var/lib/wireguard-manager wireguard-manager
```

#### Create wireguard config file and set permission with Linux ACL
```bash
touch /etc/wireguard/wg0.conf
setfacl -m wireguard-manager:rw /etc/wireguard/wg0.conf
```

#### Create environment file for wireguard-manager
```/etc/wireguard-manager/environment.conf```
```env
BASE_PATH="/"
BIND_ADDRESS="127.0.0.1:5000"
SESSION_SECRET="veryS3cr3t"
WGM_USERNAME="admin"
WGM_PASSWORD="my+password"
WGM_ENDPOINT_ADDRESS="vpn.example.com"
WGM_DNS="1.1.1.1"
WGM_MTU="1450"
WGM_PERSISTENT_KEEPALIVE="15"
WGM_CONFIG_FILE_PATH="/etc/wireguard/wg0.conf"
WGM_LOG_LEVEL="DEBUG"
# WG_CONF_TEMPLATE=
# EMAIL_FROM_ADDRESS=
# EMAIL_FROM_NAME=
# SENDGRID_API_KEY=
# SMTP_HOSTNAME=
# SMTP_PORT=
# SMTP_USERNAME=
# SMTP_PASSWORD=
# SMTP_AUTH_TYPE=
# SMTP_ENCRYPTION=
```

#### Create systemd service for wireguard-manager
```/etc/systemd/system/wireguard-manager.service```

```bash
[Unit]
Description=WireGuard Manager
ConditionPathExists=/var/lib/wireguard-manager
After=network.target

[Service]
Type=simple
User=wireguard-manager
Group=wireguard-manager

CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_NET_ADMIN CAP_NET_RAW
AmbientCapabilities=CAP_DAC_READ_SEARCH CAP_NET_ADMIN CAP_NET_RAW

WorkingDirectory=/var/lib/wireguard-manager
EnvironmentFile=/etc/wireguard-manager/environment.conf
ExecStart=/usr/local/share/applications/wireguard-manager

Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

#### TODO (maybe delete)
Create `/etc/systemd/system/wgm.service`

```bash
cd /etc/systemd/system/
cat << EOF > wgm.service
[Unit]
Description=Restart WireGuard
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/bin/systemctl restart wg-quick@wg0.service

[Install]
RequiredBy=wgm.path
EOF
```

Create `/etc/systemd/system/wgm.path`

```bash
cd /etc/systemd/system/
cat << EOF > wgm.path
[Unit]
Description=Watch /etc/wireguard/wg0.conf for changes

[Path]
PathModified=/etc/wireguard/wg0.conf

[Install]
WantedBy=multi-user.target
EOF
```

Apply it

```sh
systemctl enable wgm.{path,service}
systemctl start wgm.{path,service}
```

### Using openrc

Create `/usr/local/bin/wgm` file and make it executable

```sh
cd /usr/local/bin/
cat << EOF > wgm
#!/bin/sh
wg-quick down wg0
wg-quick up wg0
EOF
chmod +x wgm
```

Create `/etc/init.d/wgm` file and make it executable

```sh
cd /etc/init.d/
cat << EOF > wgm
#!/sbin/openrc-run

command=/sbin/inotifyd
command_args="/usr/local/bin/wgm /etc/wireguard/wg0.conf:w"
pidfile=/run/${RC_SVCNAME}.pid
command_background=yes
EOF
chmod +x wgm
```

Apply it

```sh
rc-service wgm start
rc-update add wgm default
```

### Using Docker

Set `WGM_MANAGE_RESTART=true` to manage WireGuard interface restarts.
Using `WGM_MANAGE_START=true` can also replace the function of `wg-quick@wg0` service, to start WireGuard at boot, by
running the container with `restart: unless-stopped`. These settings can also pick up changes to WireGuard Config File
Path, after restarting the container. Please make sure you have `--cap-add=NET_ADMIN` in your container config to make
this feature work.

Set `WGM_MANAGE_RELOAD=true` to manage WireGuard interface reload.
Using `WGM_MANAGE_RELOAD=true` will use `wg syncconf wg0 /path/to/file` to update the WireGuard running-configuration
without restart. Please make sure you have `--cap-add=NET_ADMIN` in your container config to make this feature work.

## Build

### Build docker image

Go to the project root directory and run the following command:

```sh
docker build --build-arg=GIT_COMMIT=$(git rev-parse --short HEAD) -t wireguard-manager .
```

or

```sh
docker compose build --build-arg=GIT_COMMIT=$(git rev-parse --short HEAD)
```

:information_source: A container image is available on [Docker Hub](https://hub.docker.com/r/swissmakers/wireguard-manager)
which you can pull and use

```
docker pull swissmakers/wireguard-manager
````

### Build binary file

Prepare the assets directory

```sh
./prepare_assets.sh
```

Then build your executable

```sh
go build -o wireguard-manager
```

## License

MIT. See [LICENSE](https://github.com/swissmakers/wireguard-manager/blob/master/LICENSE).
