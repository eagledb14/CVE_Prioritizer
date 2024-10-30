#!/usr/bin/env python3

__author__ = "Mario Rojas"
__license__ = "BSD 3-clause"
__version__ = "1.5.1"
__maintainer__ = "Mario Rojas"
__status__ = "Production"

import re
import threading
from threading import Semaphore

import click
from dotenv import load_dotenv

from scripts.constants import LOGO
from scripts.constants import SIMPLE_HEADER
from scripts.constants import VERBOSE_HEADER
from scripts.helpers import worker

load_dotenv()
Throttle_msg = ''


# argparse setup
@click.command()
@click.option('-c', '--cve', type=str, help='Unique CVE-ID')
@click.option('-e', '--epss', type=float, default=0.2, help='EPSS threshold (Default 0.2)')
@click.option('-f', '--file', type=click.File('r'), help='TXT file with CVEs (One per Line)')
@click.option('-n', '--cvss', type=float, default=6.0, help='CVSS threshold (Default 6.0)')
@click.option('-o', '--output', type=click.File('w'), help='Output filename')
@click.option('-t', '--threads', type=int, default=100, help='Number of concurrent threads')
@click.option('-v', '--verbose', is_flag=True, help='Verbose mode')
@click.option('-l', '--list', help='Comma separated list of CVEs')
@click.option('-nc', '--no-color', is_flag=True, help='Disable Colored Output')
def main(cve, epss, file, cvss, output, threads, verbose, list, no_color):
    # Global Arguments
    color_enabled = not no_color

    # standard args
    header = SIMPLE_HEADER
    epss_threshold = epss
    cvss_threshold = cvss
    sem = Semaphore(threads)

    # Temporal lists
    cve_list = []
    threads = []

    if verbose:
        header = VERBOSE_HEADER
    if cve:
        cve_list.append(cve)
        click.echo(LOGO + header)
    elif list:
        cve_list = list.split(',')
        click.echo(LOGO + header)
    elif file:
        cve_list = [line.rstrip() for line in file]
        click.echo(LOGO + header)

    if output:
        output.write("cve_id,priority, epss, cvss, version, severity, cisa_kev, vendor, product" + "\n")
        pass

    for cve in cve_list:
        if not re.match(r'(CVE|cve-\d{4}-\d+$)', cve):
            click.echo(f'{cve} Error: CVEs should be provided in the standard format CVE-0000-0000*')
        else:
            sem.acquire()
            t = threading.Thread(target=worker, args=(cve.upper().strip(), cvss_threshold, epss_threshold, verbose,
                                                      sem, color_enabled, output))
            threads.append(t)
            t.start()

    for t in threads:
        t.join()


if __name__ == '__main__':
    main()
