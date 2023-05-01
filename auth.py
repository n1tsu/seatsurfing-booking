from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.wait import WebDriverWait
from seleniumwire import webdriver

import json
import logging
import pyotp
import re
import time


log = logging.getLogger(__name__)
logging.getLogger('seleniumwire').setLevel(logging.ERROR)
logging.getLogger('selenium').setLevel(logging.ERROR)

def prepare_driver():
    # No UI
    options = Options()
    options.headless = True
    # Firefox and no proxy
    profile = webdriver.FirefoxProfile()
    profile.set_preference('network.proxy.Kind','Direct')
    driver = webdriver.Firefox(profile, options=options)
    # Wait if not finding component
    driver.implicitly_wait(10)
    return driver


def authentication_gitlab(
        username: str, password: str,
        otp_secret: str, link: str
) -> (str, str):
    """Authenticate with gitlab oauth link using username, password and 2FA OTP.
    It return the token and the refresh token.
    """
    log.info('Authenticate to Gitlab')

    driver = prepare_driver()
    driver.get(link)

    # Credentials
    login_input = driver.find_element(By.XPATH, '//*[@id="username"]')
    password_input = driver.find_element(By.XPATH, '//*[@id="password"]')
    login_input.send_keys(username)
    password_input.send_keys(password)
    password_input.send_keys(Keys.RETURN)
    log.info('Credentials entered')
    time.sleep(2)

    # Click on 2FA button
    wait = WebDriverWait(driver, 10)
    otp_button = wait.until(EC.element_to_be_clickable((By.XPATH, '//*[@id="js-login-2fa-device"]')))
    otp_button.click()

    # Retrieve OTP from secret
    totp = pyotp.TOTP(otp_secret)
    otp = totp.now()
    log.debug(otp)
    time.sleep(1)

    # OTP
    otp_input = wait.until(EC.presence_of_element_located((By.XPATH, '//*[@id="user_otp_attempt"]')))
    otp_input.send_keys(otp)
    otp_input.send_keys(Keys.RETURN)
    log.info('One Time Password entered')

    # Sleep to wait redirections and retrieve auth/verify response
    log.info('Waiting for tokens (~5 seconds)')
    time.sleep(5)

    for request in driver.requests:
        if request.response:
            if re.match('.*auth/verify.*', request.url):
                log.debug(request.url)
                response_json = json.loads(request.response.body.decode('utf8'))
                log.debug(response_json)
                driver.close()
                return response_json['accessToken'], response_json['refreshToken']

    log.error('Failed to retrieve authentication tokens')
    driver.close()
    exit(1)
