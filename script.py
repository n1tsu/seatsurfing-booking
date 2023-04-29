import argparse
import json
import requests
import time
import urllib3

from typing import Optional
from datetime import datetime, timedelta

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ARGS = None

ENDPOINT_REFRESH = "/auth/refresh"
ENDPOINT_REGISTER = "/booking/"
ENDPOINT_LOCATION = "/location/"

PROXIES = {
  "http": "",
  "https": "",
}


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def debug_response(response):
    print(f'REQUEST:')
    print(f'URL: {response.request.url}')
    print(f'Headers: {json.dumps(dict(response.request.headers), indent=4)}')
    print(f'Body: {response.request.body}')
    print(f'Method: {response.request.method}')
    print()
    print('RESPONSE')
    print(f'Status Code: {response.status_code}')
    print(f'Reason: {response.reason}')
    print(f'Headers: {json.dumps(dict(response.headers), indent=4)}')
    if response.headers.get('content-type') == 'application/json':
        print(f'JSON: {json.dumps(response.json(), indent=4)}')
    else:
        print(f'Content: {response.content}')


def retrieve_location(location_name: str) -> str:
    print(f'Retrieving id for location {location_name}')
    response = requests.get(
        ARGS.url + ENDPOINT_LOCATION,
        proxies=PROXIES,
        headers={'Authorization': f'Bearer {ARGS.token}'},
        verify=False
    )
    if response.status_code != 200 or ARGS.verbose:
        debug_response(response)
        if response.status_code != 200:
            exit(1)

    response_json = response.json()
    for location in response_json:
        if location['name'] == location_name:
            return location['id']

    print(f'Location {location_name} ' + bcolors.FAIL + 'not found' + bcolors.ENDC)


def place_available(day: datetime, location_id: str) -> Optional[str]:
    """Check space for a given day and return place-id if available, else return None.
    """
    readable_day = "{:%A %d %B}".format(day)
    print(f'Checking place {ARGS.space_name} for {readable_day}')
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
    if response.status_code != 200 or ARGS.verbose:
        debug_response(response)
        if response.status_code != 200:
            exit(1)

    response_json = response.json()
    for place in response_json:
        if place['name'] == ARGS.space_name:
            if place['available']:
                return place['id']
            people = place['bookings'][0]['userEmail']
            print(
                f'Place {ARGS.space_name} for {readable_day} is ' +
                bcolors.FAIL + 'occupied' + bcolors.ENDC + f' ({people})'
            )
            return None

    print(bcolors.FAIL + "Place wasn't found ! Exiting" + bcolors.ENDC)
    exit(1)


def register_place(day: datetime, space_id: str):
    """Register a space for a given day.
    """
    readable_day = "{:%A %d %B}".format(day)
    print(f'Register place {ARGS.space_name} for {readable_day}')
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
    if response.status_code != 201 or ARGS.verbose:
        debug_response(response)
        if response.status_code != 201:
            exit(1)
    print(
        f'Place {ARGS.space_name} for {readable_day} is ' +
        bcolors.OKGREEN + 'booked' + bcolors.ENDC
    )


def refresh_auth() -> (str, str):
    """Refresh JWT using the refresh token.
    The output is the new JWT and the new refresh token.
    """
    print(f'Refreshing token')
    refresh_payload = f'"refreshToken":"{ARGS.refresh_token}"'
    response = requests.post(
        ARGS.url + ENDPOINT_REFRESH,
        data= '{' + refresh_payload + '}',
        proxies=PROXIES,
        headers={'Authorization': f'Bearer {ARGS.token}'},
        verify=False
    )
    if response.status_code != 200 or ARGS.verbose:
        debug_response(response)
        if response.status_code != 200:
            exit(1)

    response_json = response.json()
    access_token = response_json['accessToken']
    refresh_token = response_json['refreshToken']
    print('New access token: ' + bcolors.OKCYAN + f'{access_token}' + bcolors.ENDC)
    print('New refresh token: ' + bcolors.OKCYAN + f'{refresh_token}' + bcolors.ENDC)

    return access_token, refresh_token


def main_loop():
    """Main loop checking availability and refreshing JWT.
    If a wanted place is available, register it.
    """
    running = True
    today = datetime.today()
    location_id = retrieve_location(ARGS.location_name)

    while running:
        given_day = today
        for i in range(ARGS.days):
            given_day = given_day + timedelta(days=1)
            readable_day = "{:%A %d %B}".format(given_day)
            if given_day.weekday() > 4:
                print(
                    f'{readable_day} is weekend, ' + bcolors.WARNING +
                    'skipping' + bcolors.ENDC
                )
                continue
            space_id = place_available(given_day, location_id)
            if space_id is not None:
                register_place(given_day, space_id)

        ARGS.token, ARGS.refresh_token = refresh_auth()
        print(f"Waiting for {ARGS.interval} seconds")
        time.sleep(ARGS.interval)


def init_parser():
    global ARGS
    parser = argparse.ArgumentParser(description='Register seatsurfing space inside a location for consecutive days.')
    parser.add_argument('-u', '--url', metavar='url', required=True, help='Seatsurfing URL')
    parser.add_argument('-l', '--location-name', metavar='name', dest='location_name', required=True, help='Location containing spaces')
    parser.add_argument('-s', '--space-name', metavar='name', dest='space_name', required=True, help='Space to register')
    parser.add_argument('-t', '--token', metavar='token', dest='token', required=True, help='JWT to be used for authentication (to retrieve via browser console)')
    parser.add_argument('-r', '--refresh-token', metavar='token', required=True, dest='refresh_token', help='Token used to refresh JTW (to retrieve via browser console)')
    parser.add_argument('-d', '--days', metavar='days', type=int, default=7, help='following days to register (default 7 days)')
    parser.add_argument('-i', '--interval', metavar='seconds', type=int, default=3 * 60, help='interval in seconds between checks (default 3m, must be <5m to avoid losing token)')
    parser.add_argument('-v', '--verbose', action='store_true', help='print debug')
    ARGS = parser.parse_args()


if __name__ == '__main__':
    init_parser()
    main_loop()