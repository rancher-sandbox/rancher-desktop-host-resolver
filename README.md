# Host Resolver
A stub DNS resolver that runs on the host machine on Linux, macOS, and Windows. The main goal behind this stub resolver is more robuset handling of domain name resolutions when VPN split tunnle is setup.  

![b822615f-af15-4997-981b-53a6f1153d81 sketchpad (1)](https://user-images.githubusercontent.com/10409174/161135610-6418fe36-cde0-46d2-8e88-11cab9a3b3a2.svg)

## Run

```bash
/host-resolver run -a 127.0.0.1 -t 54 -u 53 -c "host.rd.internal=111.111.111.111,host2.rd.internal=222.222.222.222"
```
NOTE: If ports are not provided, host resolver will listen on random ports.

## Test

```bash
docker build -t host-resolver:latest . && docker run --dns 127.0.0.1 -it host-resolver:latest
```
