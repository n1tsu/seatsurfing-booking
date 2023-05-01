import logging


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


def color_message(message: str, color: bcolors) -> str:
    return color + message + bcolors.ENDC


def log_response_to_file(response):
    if logging.getLogger().getEffectiveLevel() == logging.DEBUG:
        f = open("reponse_logs.txt", "a")
        response_log = (
            'REQUEST:\n'
            f'URL: {response.request.url}\n'
            f'Headers: {json.dumps(dict(response.request.headers), indent=4)}\n'
            f'Body: {response.request.body}\n'
            f'Method: {response.request.method}\n'
            '\nRESPONSE\n'
            f'Status Code: {response.status_code}\n'
            f'Reason: {response.reason}\n'
            f'Headers: {json.dumps(dict(response.headers), indent=4)}\n'
        )
        if response.headers.get('content-type') == 'application/json':
            log += f'JSON: {json.dumps(response.json(), indent=4)}\n'
        else:
            log += f'Content: {response.content}\n'

        f.write(response_log + "\n")
        f.close()
