from socket import *
import re
from struct import *


NTP_TEMPLATE = (36, 2, 0, 238, 3602, 2077,
            b'\xc1\xbe\xe6A', 0, 0, 0, 2208998900)

NTP_HEADER_FORMAT = ">BBBBII4sQQQQ"

DNS_TEMPLATE = (34097, 256, 1, 0, 0, 0, b"www.google.com", 1, 1)
DNS_HEADER_FORMAT = "HHHHHHsHH"


def isIP(adr):
    regExp = re.search(r"([0-9]{1,3}\.){3}[0-9]{1,3}", adr)
    if regExp is not None and regExp.group(0) == adr:
        return True
    return False


def scan_tcp(host, port):
    try:
        sock = socket(AF_INET, SOCK_STREAM)
        sock.settimeout(0.2)
        sock.connect((host, port))
    except ConnectionRefusedError:
        return False
    except timeout:
        return False
    if sock:
        print("Connected to {}:{}".format(host, port))
        sock.send(b"ALOHA")
        data = None
        try:
            data = sock.recv(2048)
        except ConnectionResetError:
            print("connection reset")
        except timeout:
            print("timeout")
        if data:
            print("Reply:{}".format(data))
        else:
            print("Reply: ----(No Data)")
        print("         ")

        sock.close()
        return True
    else:
        return False


def scan_udp(host, port):
    sock = socket(AF_INET, SOCK_DGRAM)
    res_proto = []
    try:
        for proto in ["NTP", "DNS"]: # "SMTP", "POP3", "HTTP"]:
            request = None
            data = None
            if proto == "NTP":
                request = pack(NTP_HEADER_FORMAT, *NTP_TEMPLATE)
            if proto == "DNS":
                request = pack(DNS_HEADER_FORMAT, *DNS_TEMPLATE)
            try:
                sock.settimeout(0.1)
                sock.sendto(request, (host, port))
                data = sock.recv(2048)

                if data:
                    res_proto.append(proto)
                    print(port, data, proto)
            except timeout:
                pass
            except TypeError:
                pass
    except Exception as e:
            print(e)
            pass
    finally:
        sock.close()
        if res_proto:
            return res_proto


def main():
    host = "127.0.1.1"
    ports = []
    for i in range(40, 60):

        ports.append(i)
    if isIP(host):
        ip = host
    else:
        ip = gethostbyname(host)
    tcp_ports = []
    udp_ports = {}
    if ip:
        print("Running scan on {}".format(host))
        print("Target IP: {}".format(ip))
        for port in ports:
            if scan_tcp(host, int(port)):
                tcp_ports.append(port)
        for port in tcp_ports:

            proto = scan_udp(host, int(port))
            if proto is not None:
                udp_ports[port] = proto

    else:
        print("ERROR: Invalid host")
    print("--------")
    print("TCP PORTS: ", tcp_ports)
    print("UDP PORTS: ", udp_ports)


if __name__ == "__main__":
        main()

