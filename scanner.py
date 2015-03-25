from socket import *
import re
from ipaddress import *
from struct import *
from threading import Thread
import argparse
global tcp_ports
global udp_ports
global closed_udp_ports

tcp_ports = []
udp_ports = {}
closed_udp_ports = []
NTP_TEMPLATE = (36, 2, 0, 238, 3602, 2077,
            b'\xc1\xbe\xe6A', 0, 0, 0, 2208998900)

NTP_HEADER_FORMAT = ">BBBBII4sQQQQ"

DNS_TEMPLATE = (34097, 256, 1, 0, 0, 0, b"www.google.com", 1, 1)
DNS_HEADER_FORMAT = "HHHHHHsHH"
IPv4_HEADER_FORMAT = "BBHHHBBHii"
ICMP_HEADER_FORMAT = "BBHi"
DGRAM_HEADER_FORMAT = "HHHH"


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
        sock.send(b"ALOHA")
        data = None
        try:
            data = sock.recv(2048)
        except ConnectionResetError:
            pass
        except timeout:
            pass
        tcp_ports.append(port)
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

                connection = socket(proto=IPPROTO_ICMP, type=SOCK_RAW)
                connection.settimeout(0.5)

                sock.settimeout(0.1)
                sock.sendto(request, (host, port))
                try:
                    data = sock.recv(2048)
                    if data:
                        if port in udp_ports:
                            if proto not in udp_ports[port]:

                                udp_ports[port].append(proto)
                        else:
                            udp_ports[port] = [proto]
                    return

                except timeout:
                    pass
                try:
                    data_icmp = connection.recvfrom(512)
                    icmp_port = unpack("H"*32, data_icmp[0][1:65])[-7]
                    closed_udp_ports.append(icmp_port)
                except timeout:
                    if port in udp_ports:
                        if proto+"|filtered" not in udp_ports[port]:
                            udp_ports[port].append(proto+"|filtered")
                    else:
                        udp_ports[port] = [proto+"|filtered"]
                    return True
                except Exception as e:
                    print(e)
                    pass
                connection.close()
            except timeout:
                pass
            except TypeError as e:
                pass

    except Exception as e:
            pass
    finally:
        sock.close()

def main(args):
    host = "127.0.1.1"

    ports = []
    start = 1
    end = 300
    if args.range:
        start = int(args.range[0])
        end = int(args.range[1])

    for i in range(start, end):

        ports.append(i)
    if isIP(host):
        ip = host
    else:
        ip = gethostbyname(host)
    udp_threads = []
    tcp_threads = []
    if ip:
        print("Running scan on {}".format(host))
        print("Target IP: {}".format(ip))
        if args.tcp:
            for port in ports:
                tcp_threads.append(Thread(target=scan_tcp, args=(host, int(port))))
                tcp_threads[-1].start()
                if len(tcp_threads) > 100:
                    for thread in tcp_threads:
                        if thread.isAlive():
                            thread.join()
                        tcp_threads.pop(0)
            tcp_threads[-1].join()

        if args.udp:
            for port in ports:
                udp_threads.append(Thread(target=scan_udp, args=(host, int(port))))
                udp_threads[-1].start()
                if len(udp_threads) > 100:
                    for thread in udp_threads:
                        if thread.isAlive():
                            thread.join()
                        udp_threads.pop(0)

            udp_threads[-1].join()

    else:
        print("ERROR: Invalid host")

    if not args.cancel and args.udp:
        print("Checking expected udp ports (-c flag to cancel this procedure)")
        for port in ports:
            if not port in closed_udp_ports:
                if scan_udp(host, port):
                    print("{}: opened".format(port))

    print("--------")
    if args.tcp:
        print("TCP PORTS: ", tcp_ports)
    if args.udp:
        print("UDP PORTS: ", udp_ports)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TCP/UDP scanner")
    parser.add_argument("host",  help='host to scan')
    parser.add_argument("-r", "--range", metavar=("FROM", "TO"),  nargs=2,  help='range of tcp ports')
    parser.add_argument("-u", "--udp", action="store_true",
                        help="scan udp ports")
    parser.add_argument("-t", "--tcp", action="store_true",
                        help="scan tcp ports")
    parser.add_argument("-c", "--cancel", action="store_true",
                        help="cancel checking expected udp ports")
    args = parser.parse_args()

    main(args)

