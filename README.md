# Learn Consul

### Consul

# Install consul
sudo yum install -y yum-utils
sudo yum-config-manager --add-repo https://rpm.releases.hashicorp.com/RHEL/hashicorp.repo
sudo yum -y install consul

# Consul Dev-Server (In memory mode)
# When running locally on mac etc.
consul agent -dev

netstat -ntlp | grep consul

Port 8500
http://localhost:8500

# When running on a server
consul agent -dev --client=0.0.0.0

consul members

server 1.2.3.4
client 5.6.7.8
#bind must be set because multiple network adresses could be on the client host
consul agent-join 1.2.3.4 -bind 5.6.7.8 -data-dir /path/dir

error because: netstat -ntlp # show 127.0.0.1:<PORTS>

exit the server and start with
consul agent -dev --client=0.0.0.0 -bind <SERVER-IP>

and the try again on client:
server 1.2.3.4
client 5.6.7.8
consul agent-join 1.2.3.4 -bind 5.6.7.8 -data-dir /path/dir

check in gui

# Remote execution

When you want to execute a command on all servers

consul exec ping -c1 google.com
# by default this will not work
consul agent -hcl 'disable_remote_exec=false' # This will enable remote execution

You have to restart the client
consul agent-join 1.2.3.4 -bind 5.6.7.8 -data-dir /path/dir -hcl 'disable_remote_exec=false' 

then on the server
consul exec ping -c1 google.com

you can also enable remote execution on the server
consul agent -dev --client=0.0.0.0 -bind <SERVER-IP> -hcl 'disable_remote_exec=false'

the command can be run on all servers and clients 

# Configuration Directory

Can be in json or hcl format

config agent --config-dir /root/consul-config/

vi consul.hcl
```
data_dir = "/root/consul"
start_join = ["134.209.155.89"] # Server
bind_addr = "165.22.222.190" # Client
```
Start server
consul agent -config-dir=/root/consul-config/

you can also skip parts in the config file and use them in the cli command parameters

# Leave Behavior in Consul

The client tells the server that he leaves

There are 2 options:
- Gracefull Exit = The Agent informs the server that it is leaving. Also when Ctr+C: killall -s 2 consul
- Force Removal = Datacenter will detect failure. Agent is not available: killall -s 9 consul

# Consul Server Mode for Production

Important Flags:
-server # You want to start this node in server mode
-bootstrap-expect # The number of servers in the cluster
-node # The name of this node. By default consul uses the hostname but they could be doubled
-bind and -data-dir # Adress agent will listen and storing data
-config-dir # The path to the config files. Standard is /etc/consul.d

consul agent -server -bootstrap-expect 1 -node consul-server -bind <my-ip-from-this-node> -client 0.0.0.0 -data-dir /root/consul

UI does not work now only shows: Consul Agent as text

Add -ui true
consul agent -server -bootstrap-expect 1 -node consul-server -bind <my-ip-from-this-node> -client 0.0.0.0 -data-dir /root/consul -ui true

vi /root/consul-server-config/consul.hcl
```
data_dir = "/root/consul"
bind_addr = "134.209.155.89"
client_addr = "0.0.0.0"
bootstrap_expect = 1
node_name = "consul-server"
ui = true
server = true
```

consul agent -config-dir /root/consul-server-config/

# Systemd and Consul

vi /usr/lib/systemd/consul.service
```
[Unit]
Description="HashiCorp Consul - A service mesh solution"
Documentation=https://www.consul.io
Requires=network-online.target
After=network-online.target
ConditionFileNotEmpty=/etc/consul.d/consul.hcl

[Service]
User=consul
Group=consul
ExecStart=/usr/bin/consul agent -config-dir=/etc/consul.d/
ExecReload=/usr/bin/consul reload
ExecStop=/usr/bin/consul leave
KillMode=process
Restart=on-failure
LimitNOFILE=65536
```

If you installed consul with yum, dnf or apt the systemd file will always be there.

systemctl status consul
then you can see the path of the file in the output

then there also is a conf file in /etc/consul.hcl
but it is very big.
For learning it is better to start with an easy one.

cat /root/cosul-new-config/consul.hcl

mv /etc/consul.d/consul.hcl /etc/consul.d/consul.bak

cp /root/consul-new-config/consul.hcl /etc/consul.d/consul.hcl

systemctl restart consul

# Because of the service file content
chown consul:consul /etc/consul.d/consul.

systemctl start consul

#error
journalctl -u consul

change in /etc/consul.d/consul.hcl
data_dir = "/etc/consul.d/consul-dir"

systemctl restart consul
systemctl enable consul

check in gui

# Service Discovery

# When you want the ips if an service from Consul from the consul service (only from servers in the consul cluster)
dig @localhost -p 8600 messaging-service.service.consul

dig @localhost -p 8600 messaging-service.service.consul SRV # shows also the port

# Register a service
we have to write an service definition file

In this example we have a server and client running with systemd

Server
```
data_dir
bind_addr
client_addr
bootstrap_expect
node_name
ui
server
```

Client
```
start_join
bind_addr
data_dir
```


service definition file

on client

vi /etc/consul.d/web.json
```
{
  "service": {
    "name": "web",
    "port": 80
  }
}
```

consul validate /etc/consul.d/

consul reload

Check under services in the GUI

# Finding a service

Install dig
yum install bind-utils

dig @localhost -p 8600 messaging-service.service.consul

dig syntax:
dig google.com # shows IP of dns and type fx. A record

defaults to the dns server configured on the system in:
/etc/resolv.conf

But we wand to ask the dns server on port 8600
shown with netstat -ntlp

dig @localhost -p 8600 web.service.consul SRV

# Monitoring the service

3 Health check types
- Script + Internal
- HTTP + Internal
- TCP + Internal

We focus on Script Check now
Exit Code must be 
0 = OK
1 = WARNING
Any other code = ERROR

Check definition
A HTTP check
```
{
 
}
```


A script check
```
{
  "check": {
    "id": "mem-util",
    "name": "Memory utilization",
    "args": ["/usr/local/bin/check_mem.py", "-limi", "256MB"],
    "interval": "10s",
    "timeout": "1s"
  }
}
```

We now write an check for our web service
In the client in /etc/consul.d/web.json
```
{
  "service": {
    "name": "web",
    "port": 80,
    "check": {
      "args": [
        "curl",
        "127.0.0.1"
      ],
      "interval": "10s"
    }
  }
}
```
consul reload
Error scripts are disabled on this agent

vi /etc/consul.d/consul.hcl
```
enable_local_script_checks = true
```
consul reload
systemctl restart consul
consul reload

Check in GUI under service checks. Shows an error

check with curl localhost:80

yum install nginx
start nginx
curl localhost:80

check in gui under service checks

dig @<server consul ip> -p 8600 web.service.consul SRV

when nginx is stoped the command would not show an ip for the service

# Key Value Store

In UI you can see the key value store

or in cli
consul kv put <key> <value>
consul kv put max_memory 512MB

consul kv get <key>

consul kv delete <key>

consul kv list

consul kv export

consul kv import

consul kv get -recurse

kv can also be access by HTTP API

# Watches

Check for changes in the key value store

Then an external handler can be executed. For example: a script


consul watch -type=key -key=max_mem

In the output the value is base64 encrypted
echo "dhdhdh=" | base64 -d

mkdir /root/tmp_consul
cd /root/tmp_consul
vi myscript.sh
```
#!/bin/env sh
while read watch
do
  echo $watch
done
```

chmod +x myscript.sh
consul watch -type=key -key=max_mem ./myscript.sh

consul watch -type checks -state critical
stop nginx and the health check will fail

You can integrate the check in slack and give an message

# Consul Template

Consul template is an different binary

consul-template -h

In The Template: {{ key "course-name"}}
You can also fetch ip nodename etc.

In Github: hashicorp/consul-template: https://github.com/hashicorp/consul-template

Download from: https://releases.hashicorp.com/consul-template

wget https://releases.hashicorp.com/consul-template/0.37.4/consul-template_0.37.4_linux_amd64.zip

https://github.com/hashicorp/consul-template/tree/main/examples

unzip consul-template_0.37.4_linux_amd64.zip

mv consul-template /usr/local/bin

consul-template -h

vi cource.tpl
```
{{ key "course" }}
```

consul-template -template "course.tpl:course_name.txt"
consul-template -once -template "course.tpl:course_name.txt" -once

Configuration:
```
consul {
  address = "127.0.0.1:8500"
}
template {
  source = "/root/template/course.tpl"
  destination = "/root/template/course_newname.txt"
  command = "echo Modified > /root/template/delta.txt"
}
```
consul-template -config "/root/test/template/template.hcl"

Can be used to edit the config of a webserver and restart it



# Envconsul

Dynamic App configuration

Lanch an App witch env from Consul or Vault

Given KV in Consul or Vault
address 1.2.3.4
max_conns 5
port 80

envconsul -prefix my-app env | egrep "address|max_conns|port"

For docker you can use the env variables
envconsul -prefix my-app env | docker -e ADRESS=${address}

git clone https://github.com/hashicorp/envconsul.git

cd envconsul

make dev

yum whatprovides make

yum install make

make dev

yum whatprovides go

yum install golang

make dev

ll /root/go/bin
envconsul

cp envconsul /usr/local/bin

Test:
consul agent -dev
consul kv put my-app/address 1.2.3.4
consul kv put my-app/max_conns 5
consul kv put my-app/port 80  

consul kv get -recurse my-app

Shows the env vars
envconsul -prefix my-app env

# Consul Connect

Service to service connection though tls

Frontend Service <=> Backend Service

Though local Proxies on the vms

Example:

You have to services on two vms
curl localhost:9080

netstat -ntlp
0.0.0.0:9080

There ist also a port 5000 that is open. That is the port for the proxy

Backend service
curl localhost:8080

8080 => Frontend Service => 5000

Locally also works:
curl localhost:5000

In the GUI go to Intentions Tab and Create new Intention
Source Service = frontend-service
Destination Service = backend-service
Deny = true

curl localhost:5000 does not work anymore

# Implement Consul Connect

In Rhel deactivate SELinux
getenforce
$ Enforcing

setenforce 0

or vi /etc/selinux/config
```
SELINUX=disabled
```

getenforce
$ Permissive

yum install nginx
cd /etc/nginx/conf.d
vi services.conf
```
server {
  listen 8080;
  server_name _;
  location / {
    proxy_pass http://127.0.0.1:5000;
  }
}


server {
  listen 9080;
  server_name _;
  root /usr/share/nginx/html/backend-service; # Serve the content in this folder
}
```
mkdir /usr/share/nginx/html/backend-service
vi /usr/share/nginx/html/backend-service/index.html
```
<html>
  <h1>Backend Service</h1>
</html>
```
nginx -t
#nginx -s reload
systemctl start nginx
systemctl enable nginx
systemctl status nginx

netstat -ntlp

curl localhost:8080
Bad Gateway 502

curl localhost:9080
Backend Service

Create Service Definition
Backend Service:
```
service {
  name = "backend-service"
  id = "backend-service"
  port = 9080

  connect {
    sidecar_service {}
  }

  check {
    id = "backend-service"
    http = "http://localhost:9080"
    method = "GET"
    interval = "1s"
    timeout = "1s"
  }
}
```
cd /tmp
vi backend-service.hcl
```
service {
  name = "backend-service"
  id = "backend-service"
  port = 9080

  connect {
    sidecar_service {}
  }

  check {
    id = "backend-service"
    http = "http://localhost:9080"
    method = "GET"
    interval = "1s"
    timeout = "1s"
  }
}
```
consul services register backend-service.hcl

start consul in dev mode
consul agent -dev --client=0.0.0.0
consul services register backend-service.hcl

vi frontend-service.hcl
```
service {
  name = "frontend-service"
  id = "frontend-service"
  port = 8080

  connect {
    sidecar_service {
      proxy {
        upstreams = [
          {
            destination_name = "backend-service"
            local_bind_port = 5000
          }
        ]
      }
    }
  }

  check {
    id = "backend-service-check"
    http = "http://localhost:8080"
    method = "GET"
    interval = "1s"
    timeout = "1s"
  }
}
```
consul services register frontend-service.hcl

Check in GUI under Services Tab
There are errors because the sidecar proxys are not created

Start sidecar proxys:
consul connect proxy -sidecar-for frontend-service > /tmp/frontend-service.log &
consul connect proxy -sidecar-for backend-service > /tmp/backend-service.log &

netstat -ntlp
You can see port 5000

Check in GUI
All services are green

curl localhost:8080
Backend Service

curl localhost:5000
Backend Service


You can now go to Intentions and create an new one
Frontend => Backend

Check Deny and then allow in the GUI Intentions

curl localhost:8080
Backend Service

curl localhost:5000
Backend Service

Now also check the logs in /tmp/frontend-service.log and /tmp/backend-service.log

# Intensions and Prcedence

Also in the cli:

Allow web to talk to db
consul intention create web db

Deny db to talk to any service. db => any
consul intention create -deny db "*"

Checks whether a connection attempt between two services would be authorized given the current set of intentions and consul configuration
consul intention check web db
consul intention check frontend-service backend-service
Allowed

Find all intentions for communicating to the db service
consul intention match db

consul.io/docs/intentions look at precendence

# Sidecar Proxy Support

The buildin sidecar proxy is for dev and testing

But for Prod you can use Envoy as a sidecar proxy

Envoy can make trafic split to two services
60% traffic to service version1, 40% traffic to service version2
And also load balancing

# Consul ACLs

cd /etc/consul.d

vi agent.hcl
```
acl = {
  enabled = true
  default_policy = "deny"
  enable_token_persistence = true
}
```
rm -rf consul-dir/

systemctl start consul
systemctl enable consul
systemctl status consul 

Check in GUI its asking to login

Check in cli that also does not work anymore
consul members



Create a bootstrap token
consul acl bootstrap
SecretID: Use this as the token to log into the gui

In cli
consul members -token dshshdshdhsdhsdhshdhdhsdh

You can also set an env variable with the token content
export CONSUL_HTTP_TOKEN=dshshdshdhsdhsdhshdhdhsdh

# Understanding ACL Rules

You can create multible tokens with diferent policies

With an ACL Policy

Write access to key value store
```
key_prefix "mobiles/" {
  policy = "write"
}
```

Read access to key value store
```
key_prefix "mobiles/" {
  policy = "read"
}
```

Login into the gui
Tab ACL
Then into Tab Policies in ACL tab

But first create a Token in the ACL tab
comment: This token is for developers

Copy the token and login again

logout and login with the admin token
Create a kv
mobiles/motorola => Hello Moto

Create a new policy
demo-kv-policy
```
key_prefix "mobiles/" {
  policy = "read"
}
```

then: Open the new token and in the policy select box select the policy demo-kv-policy

Create kv
samsung => Hello Samsung

demo-kv-policy
```
key_prefix "mobiles/" {
  policy = "read"
}

key_prefix "mobiles/samsung" {
  policy = "deny"
}
```

Create kv
max_memory => 512MB

demo-kv-policy
```
key_prefix "" {
  policy = "read"
}
```
You can see all = wildcard

# ACL Roles

Allows grouping of policies

# Anonymous Tokens

Create a policy

anonymous-policy
```
service_prefix "" {
  policy = "read"
}
key_prefix "" {
  policy = "read"
}
node_prefix "" {
  policy = "read"
}
```

Then add to anonymious token

# Enabling ACLs on Agents

journalctl -u consul

There are many messages with: Node info update blocked by ACLs

Create policy for Agent token

In Gui Policy name: agent-token
```
node_prefix "" {  # better add node name here. But for simple example it is ok
  policy = "write"
}
service_prefix "" {
  policy = "read"
}
```

Add token in configuration in gui

Create new token: agent-token and add agent-token policy
Copy the new token i the gui




```
acl = {
  enabled = true
  default_policy = "deny"
  enable_token_persistence = true
  tokens {
    "agent" = "dhdhd-ddhdh-jdjdj-ddkkd" # token from above
  }
}
```
/etc/consul.d/agent.hcl and replace with above

systemctl restart consul

journalctl -u consul

All warnings are gone


when we delete the anomymous policy
dig @localhost -p 8600 consul.service.consul 
A Record dont show ip address

# Overwiev of Gossip Protocol (Peer to peer communication)

Unicast sends to one ip
Multicast sends to multible ips

# Enable Gossip Encryption

Two steps
1. Generate key
2. Add key to config

consul keygen

Add to consul.hcl
```
...
encrypt = "kUdLjgJ4dIi5F0Y0k2iKlTbNfQ1nHbI0"
``` 

On server one
yum install tcpdump
tcpdump -i any port 8301

you can see udp

tcpdump -i any port 8301 -vv -X
the control+c
There you can see plain text infos

Test:
consul keygen
consul agent -dev -client=0.0.0.0 -bind 1.2.3.4 -encrypt kUdLjgJ4dIi5F0Y0k2iKlTbNfQ1nHbI0
Now in the output you can see: Encrypt Gossip: true

From the second node try to connect:
consul agent -bind 1.2.3.4 -join 4.5.6.7 -data-dir /root/consul
=Error
consul agent -bind 1.2.3.4 -join 4.5.6.7 -data-dir /root/consul -encrypt kUdLjgJ4dIi5F0Y0k2iKlTbNfQ1nHbI0

On node 2 check:
tcpdump -i any port 8301 -vv -X
the control+c
All data is encrypted

# Configuring Gossip for existing datacenters

```
encrypt = "kUdLjgJ4dIi5F0Y0k2iKlTbNfQ1nHbI0"
emcrypt_verify_incoming = true
encrypt_verify_outgoing = true
```

For Gossip udp and tcp can be used
Port is: 8301

Step 1: Generate keygen
Step 2: Set encrypt_verify_incomming and encrypt_verify_outgoing to false and restart
Step 3: Set encrypt_verify_outgoing to true and restart
Step 4: Set encrypt_verify_incomming to true and restart

On server
rm data dir in /etc/consul.d for a fresh test
vi /etc/consul.d/consul.hcl
```

```

# Rotating Gossip Encryption Key

consul keyring -list

4 Steps
1. Generate new key
2. Add key to keyring
3. Promote new key to primary
4. Remove old key from keyring

1. consul keygen
2. consul keyring -install new_mykey
3. consul keyring -use new_mykey
4. consul keyring -remove old_mykey

Important!!!
The key in the config file is only needed when the node joines the cluster

cd /etc/consul.d/sonsul-dir/serf
cat local.keyring
shshsj-sjsjsjjs-jsjjjs

You can remove the encrypt parameter from the config test_filter

# RPC Encryption with TLS

The consul client => server communication goes
over RPC port 8300

The server => server goes over TCP/8300
The Client => Client goes over TCP/UDP/8301

Create a kv: sensitive-data=password123
In the server run: tcpdump -i any  8300 -vv -X
In client first check: consul members
In the client: consul kv get sensitive-data
Then check in server: tcpdump -i any  8300 -vv -X
You can see password123

That show noot only encryption in the Gossip network is important but 
also in the RPC network between Client and Server

So, we now enable RPC encryption between client and server
Three steps
1. Initialize In-Built CA (You can use built in CA by consul or use 3rd party private CAs)
2. Create server certificates
3. Configure Servers and Clients

1. consul tls ca create
2. consul tls cert create -server
3. vi /etc/consul.d/consul.hcl
Server Configuration
```
verify_incoming = true,
verify_outgoing = true,
verify_server_hostname = true,
ca_file = "consul-agent-ca.pem",
cert_file = "/etc/consul.d/dc-server-consul-0.pem",
key_file = "/etc/consul.d/dc1-server-consul-0-key.pem",
auto_encrypt = {
  allow_tls = true
}
```

Client Configuration
```
verify_incoming = false,
verify_outgoing = true,
verify_server_hostname = true,
ca_file = "consul-agent-ca.pem"
auto_encrypt = {
  tls = true
}
```
