from __future__ import print_function
import argparse
import logging

from lib import inputDetector
from lib import overflowDetector
from lib import overflowExploiter
from lib import overflowExploitSender
from lib import protectionDetector
from lib import winFunctionDetector

logging.disable(logging.CRITICAL)
logging.getLogger().disabled = True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('file', help="File to analyze")
    parser.add_argument('-l', '--libc', help="libc to use")
    parser.add_argument('-u', '--url', help="Remote URL to pwn", default="")
    parser.add_argument('-p', '--port', help="Remote port to pwn", default="0")
    parser.add_argument('-v', '--verbose', help="Verbose mode", action="store_true", default=False)
    parser.add_argument('-m', '--maxpkt', help="Max packet size", default=None, type=int)

    args = parser.parse_args()
    if args.file is None:
        print("[-] Exitting no file specified")
        exit(1)
    if args.verbose:
        logging.disable(logging.CRITICAL)

    # Detect problem type
    properties = dict()

    properties['libc'] = args.libc
    properties['file'] = args.file
    properties['input_type'] = inputDetector.checkInputType(args.file)
    print("[+] Checking pwn type...")
    print("[+] Checking for overflow pwn type...")
    properties['pwn_type'] = overflowDetector.checkOverflow(args.file, args.maxpkt, inputType=properties['input_type'])

    # Get problem mitigations
    print("[+] Getting binary protections")
    properties['protections'] = protectionDetector.getProperties(args.file)

    # Is there an easy win function
    properties['win_functions'] = winFunctionDetector.getWinFunctions(args.file)

    # Exploit overflows
    if properties['pwn_type']['type'] == "Overflow":
        print("[+] Exploiting overflow")
        properties['pwn_type']['results'] = overflowExploiter.exploitOverflow(args.file, properties,
                                                                              inputType=properties['input_type'])

        if 'input' in properties['pwn_type']['results'] and properties['pwn_type']['results']['input']:
            properties['send_results'] = overflowExploitSender.sendExploit(args.file, properties)
            if properties['send_results']['flag_found'] and args.url != "":
                properties['remote_results'] = overflowExploitSender.sendExploit(args.file, properties,
                                                                                 remote_server=True,
                                                                                 remote_url=args.url,
                                                                                 port_num=int(args.port))
    else:
        print("[-] Can not determine vulnerable type")


if __name__ == '__main__':
    main()
