#!/usr/bin/env python3
# This file contains the functions that create the reports

import os
import requests

import click
from dotenv import load_dotenv
from termcolor import colored

from scripts.constants import EPSS_URL
from scripts.constants import NIST_BASE_URL
from scripts.constants import VULNCHECK_BASE_URL

__author__ = "Mario Rojas"
__license__ = "BSD 3-clause"
__version__ = "1.5.2"
__maintainer__ = "Mario Rojas"
__status__ = "Production"

load_dotenv()

def colored_print(priority):
    """
    Function used to handle colored print
    """
    if priority == 'Priority 1+':
        return colored(priority, 'red')
    elif priority == 'Priority 1':
        return colored(priority, 'red')
    elif priority == 'Priority 2':
        return colored(priority, 'yellow')
    elif priority == 'Priority 3':
        return colored(priority, 'yellow')
    elif priority == 'Priority 4':
        return colored(priority, 'green')


# Truncate for printing
def truncate_string(input_string, max_length):
    """
    Truncates a string to a maximum length, appending an ellipsis if the string is too long.
    """
    if len(input_string) > max_length:
        return input_string[:max_length - 3] + "..."
    else:
        return input_string


# Function manages the outputs
def print_and_write(working_file, cve_id, priority, epss, cvss_base_score, cvss_version, cisa_kev,
                    verbose, action, no_color):
    color_priority = colored_print(priority)

    if verbose:
        if no_color:
            click.echo(f"{cve_id:<18}{color_priority:<22}{epss:<9}{cvss_base_score:<6}"
                f"{cvss_version:<10}{cisa_kev:<10}{truncate_string(action, 50):<53}")
        else:
            click.echo(f"{cve_id:<18}{priority:<22}{epss:<9}{cvss_base_score:<6}"
                f"{cvss_version:<10}{cisa_kev:<10}{truncate_string(action, 50):<53}")
    else:
        if no_color:
            click.echo(f"{cve_id:<18}{color_priority:<22}")
        else:
            click.echo(f"{cve_id:<18}{priority:<13}")
    if working_file:
        working_file.write(f"{cve_id},{priority},{epss},{cvss_base_score},"
                    f"{cvss_version},{cisa_kev},{action}\n")

def shodan_check(cve_id):
    response = requests.get(f"https://cvedb.shodan.io/cve/{cve_id}")
    data = response.json()
    
    cvss = 0
    version = "CVSS 1.0"
    if (data['cvss_v2'] != None):
        cvss = data['cvss_v2']
        version = "CVSS 2.0"
    else:
        cvss = data['cvss']

    epss = data['epss']

    kev = data['kev']

    action = data['summary']

    return (cvss, epss, kev, version, action)

# Main function
def worker(cve_id, cvss_score, epss_score, verbose_print, sem, colored_output, save_output=None, api=None, nvd_plus=None):
    """
    Main Function
    """

    (cve_result, epss_result, kev, version, summary) = shodan_check(cve_id)

    working_file = None
    if save_output:
        working_file = save_output

    try:
        if (kev == True):
            print_and_write(working_file, cve_id, 'Priority 1+', epss_result, cve_result,
                            version, 'TRUE', verbose_print, summary, colored_output)
        elif cve_result >= cvss_score:
            if epss_result >= epss_score:
                print_and_write(working_file, cve_id, 'Priority 1', epss_result, cve_result,
                            version, 'FALSE', verbose_print, summary, colored_output)
            else:
                print_and_write(working_file, cve_id, 'Priority 2', epss_result, cve_result,
                            version, 'FALSE', verbose_print, summary, colored_output)
        else:
            if epss_result >= epss_score:
                print_and_write(working_file, cve_id, 'Priority 3', epss_result, cve_result,
                            version, 'FALSE', verbose_print, summary, colored_output)
            else:
                print_and_write(working_file, cve_id, 'Priority 3', epss_result, cve_result,
                            version, 'FALSE', verbose_print, summary, colored_output)
    except (TypeError, AttributeError):
        pass

    sem.release()
