from seleniumwire import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import json
import time
import pyotp
import re


def authentication_gitlab(
        username: str, password: str,
        otp_secret: str, link: str
) -> (str, str):
    """Authenticate with gitlab oauth link using username, password and 2FA OTP.
    It return the token and the refresh token.
    """
    print('Authenticate to Gitlab with Selenium')
    options = Options()
    options.disable_encoding = True
    options.headless = True
    profile = webdriver.FirefoxProfile()
    profile.set_preference('network.proxy.Kind','Direct')
    driver = webdriver.Firefox(profile, options=options)
    driver.get(link)
    driver.implicitly_wait(10)
    login_input = driver.find_element(By.XPATH, '//*[@id="username"]')
    password_input = driver.find_element(By.XPATH, '//*[@id="password"]')
    login_input.send_keys(username)
    password_input.send_keys(password)
    password_input.send_keys(Keys.RETURN)
    print('Credentials entered')

    time.sleep(2)
    wait = WebDriverWait(driver, 10)
    otp_button = wait.until(EC.element_to_be_clickable((By.XPATH, '//*[@id="js-login-2fa-device"]')))
    otp_button.click()

    print('2FA OTP selected')
    totp = pyotp.TOTP(otp_secret)
    otp = totp.now()

    time.sleep(2)
    otp_input = wait.until(EC.presence_of_element_located((By.XPATH, '//*[@id="user_otp_attempt"]')))
    otp_input.send_keys(otp)
    otp_input.send_keys(Keys.RETURN)
    print('OTP entered')

    time.sleep(7)

    for request in driver.requests:
        if request.response:
            if re.match('.*auth/verify.*', request.url):
                response_json = json.loads(request.response.body.decode('utf8'))
                driver.close()
                return response_json['accessToken'], response_json['refreshToken']

    driver.close()
    exit(1)
