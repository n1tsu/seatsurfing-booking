import argparse
import html
import json
import os
import re
import requests
import time
import urllib3
import logging

from auth import authentication_gitlab
from datetime import datetime, timedelta
from typing import Optional
from debug import color_message, log_response_to_file

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
log = logging.getLogger('booking')

ARGS = None

ENDPOINT_LOCATION = "/location/"
ENDPOINT_REFRESH = "/auth/refresh"
ENDPOINT_REGISTER = "/booking/"

PROXIES = {
  "http": "",
  "https": "",
}


def retrieve_location(location_name: str) -> str:
    """Return ID of a location.
    """
    log.debug(f'Retrieving id for location {location_name}')
    response = requests.get(
        ARGS.url + ENDPOINT_LOCATION,
        proxies=PROXIES,
        headers={'Authorization': f'Bearer {ARGS.token}'},
        verify=False
    )
    if response.status_code != 200:
        log_response_to_file(response)
        if response.status_code != 200:
            exit(1)

    response_json = response.json()
    for location in response_json:
        if location['name'] == location_name:
            return location['id']

    log.error(f'Location {location_name} not found')


def place_available(day: datetime, location_id: str) -> Optional[str]:
    """Check space for a given day and return place-id if available, else return None.
    """
    compressed_day = "{:%d/%m}".format(day)
    morning = day.replace(hour=8, minute=00, second=00, microsecond=00).isoformat(timespec='milliseconds')
    evening = day.replace(hour=19, minute=00, second=00, microsecond=00).isoformat(timespec='milliseconds')
    time_payload = f'"enter":"{morning}Z","leave":"{evening}Z"'

    endpoint_availability = f"/location/{location_id}/space/availability"
    response = requests.post(
        ARGS.url + endpoint_availability,
        data= '{' + time_payload + '}',
        proxies=PROXIES,
        headers={'Authorization': f'Bearer {ARGS.token}'},
        verify=False
    )
    if response.status_code != 200:
        log_response_to_file(response)
        if response.status_code != 200:
            exit(1)

    response_json = response.json()
    for place in response_json:
        if place['name'] == ARGS.space_name:
            if place['available']:
                log.info(f'[{ARGS.space_name}] - {compressed_day} : free')
                return place['id']
            people = place['bookings'][0]['userEmail']
            log.info(f'[{ARGS.space_name}] - {compressed_day} : occupied ({people})')
            return None

    log.error("Place wasn't found ! Exiting")
    exit(1)


def register_place(day: datetime, space_id: str):
    """Register a space for a given day.
    """
    compressed_day = "{:%d/%m}".format(day)
    morning = day.replace(hour=8, minute=00, second=00, microsecond=00).isoformat(timespec='milliseconds')
    evening = day.replace(hour=19, minute=00, second=00, microsecond=00).isoformat(timespec='milliseconds')
    register_payload = f'"enter":"{morning}Z","leave":"{evening}Z","spaceId":"{space_id}"'

    response = requests.post(
        ARGS.url + ENDPOINT_REGISTER,
        data='{' + register_payload + '}',
        proxies=PROXIES,
        headers={'Authorization': f'Bearer {ARGS.token}'},
        verify=False
    )
    if response.status_code != 201:
        log_response_to_file(response)
        if response.status_code != 201:
            log.error(f'Failed to book: {response.status_code}')
            exit(1)
    log.info(f'[{ARGS.space_name}] - {compressed_day} : booked')


def refresh_auth() -> (str, str):
    """Refresh JWT using the refresh token.
    The output is the new JWT and the new refresh token.
    """
    log.info('Refreshing token')
    refresh_payload = f'"refreshToken":"{ARGS.refresh_token}"'
    response = requests.post(
        ARGS.url + ENDPOINT_REFRESH,
        data= '{' + refresh_payload + '}',
        proxies=PROXIES,
        headers={'Authorization': f'Bearer {ARGS.token}'},
        verify=False
    )
    if response.status_code != 200:
        log_response_to_file(response)
        if response.status_code != 200:
            exit(1)

    response_json = response.json()
    access_token = response_json['accessToken']
    refresh_token = response_json['refreshToken']
    log.debug(f'New access token: {access_token}')
    log.debug(f'New refresh token: {refresh_token}')

    return access_token, refresh_token


def retrieve_oauth_id() -> str:
    """Retrieve auth provider id via API.
    """
    log.debug('Retrieving oauth id')
    endpoint_singleorg = '/auth/singleorg'
    response = requests.get(
        ARGS.url + endpoint_singleorg,
        proxies=PROXIES,
        verify=False
    )
    if response.status_code != 200:
        log_response_to_file(response)
        if response.status_code != 200:
            exit(1)

    response_json = response.json()
    # XXX Assuming that the required provider is the first one
    oauth_id = response_json["authProviders"][0]["id"]
    oauth_name = response_json["authProviders"][0]["name"]
    log.debug(f'oauth provider is {oauth_name} ({oauth_id})')
    return oauth_id


def generate_auth_link(oauth_id: str) -> str:
    """Retrieve gitlab auth link via API.
    """
    log.debug('Generating authentication link')
    endpoint_auth = f'/auth/{oauth_id}/login/ui'
    response = requests.get(
        ARGS.url + endpoint_auth,
        allow_redirects=False,
        proxies=PROXIES,
        verify=False
    )
    if response.status_code != 307:
        log_response_to_file(response)
        if response.status_code != 307:
            exit(1)

    # Parse response
    log.debug(response.text)
    match = re.search('<a href="(.+)">.+', response.text)
    if match is None:
        log.error('Failed to parse authentication link')
        exit(1)

    return match.group(1)


def booking():
    """Checking availability.
    If a wanted place is available, register it.
    """
    nb_book = 0
    today = datetime.today()
    location_id = retrieve_location(ARGS.location_name)

    # For the specified following days
    given_day = today
    for i in range(ARGS.days):
        given_day = given_day + timedelta(days=1)
        compressed_day = "{:%d/%m}".format(given_day)
        # We don't book weekend
        if given_day.weekday() > 4:
            log.info(f'[{ARGS.space_name}] - {compressed_day} : weekend')
            continue

        # Check if place available, and register it if True
        space_id = place_available(given_day, location_id)
        if space_id is not None:
            register_place(given_day, space_id)
            nb_book += 1

    log.info(f'{nb_book} days over {ARGS.days} have been booked')
    # ARGS.token, ARGS.refresh_token = refresh_auth()


def init_args():
    """Parse command line arguments and retrieve environment variables.
    """
    global ARGS
    parser = argparse.ArgumentParser(description='Register seatsurfing space inside a location for consecutive days.')
    parser.add_argument('-u', metavar='url', dest='url', required=True, help='seatsurfing URL')
    parser.add_argument('-l', metavar='name', dest='location_name', required=True, help='location containing spaces')
    parser.add_argument('-s', metavar='name', dest='space_name', required=True, help='space to register')
    parser.add_argument('-o', metavar='id', dest='oauth_id', help='oauth ID if website is hosting multiple org')
    parser.add_argument('-d', metavar='days', dest='days', type=int, default=7, help='following days to register (default 7 days)')
    parser.add_argument('-v', '--verbose', action='count', default=0, help='increase the verbosity level')
    ARGS = parser.parse_args()

    if ARGS.verbose == 0:
        logging.basicConfig(level=logging.WARNING)
    elif ARGS.verbose == 1:
        logging.basicConfig(level=logging.INFO)
    elif ARGS.verbose >= 2:
        logging.basicConfig(level=logging.DEBUG)

    try:
        ARGS.user = os.environ['GITLAB_USER']
        ARGS.password = os.environ['GITLAB_PASSWORD']
        ARGS.secret = os.environ['GITLAB_OTP_SECRET']
    except KeyError as e:
        log.error(f'Secrets from environment not found: {e}')
        exit(1)


if __name__ == '__main__':
    init_args()

    # If no oauth id specified, retrieve it automatically
    if ARGS.oauth_id is None:
        ARGS.oauth_id = retrieve_oauth_id()

    # Authenticate with Selenium
    link = generate_auth_link(ARGS.oauth_id)
    ARGS.token, ARGS.refresh_token = authentication_gitlab(
        ARGS.user, ARGS.password, ARGS.secret, html.unescape(link)
    )
    log.debug(f'Access token: {ARGS.token}')
    log.debug(f'Refresh token: {ARGS.refresh_token}')

    # Booking
    booking()
