#!/usr/bin/env python3
import json
import random
import secrets
import uuid
import logging
import socket

import requests
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from ctf_gameserver import checkerlib

import service.categories
import utils
import os

TIMEOUT = 10


def sign(message):
    path = os.path.join(os.path.dirname(__file__), 'private.key')
    with open(path, mode='rb') as key_file:
        key = RSA.importKey(key_file.read())
    signer = pkcs1_15.new(key)
    return signer.sign(SHA256.new(message.encode()))


def _get_random_credentials():
    return {
        'name': secrets.token_hex(16),
        'password': secrets.token_hex(16)
    }


def login_needed(func):
    def wrapper(*args, **kwargs):
        # Hacky way to get Checker Object in wrapper
        self = args[0]
        assert isinstance(self, TemplateChecker), "All decorated functions must take self as first parameter"
        account_name = str(uuid.uuid4())
        password = secrets.token_hex(16)
        payload = {
            'name': account_name,
            'password': password
        }
        try:
            req = requests.post(self.url() + "/register", data=payload, timeout=TIMEOUT)
        except requests.exceptions.Timeout:
            logging.error(f"Timeout")
            return checkerlib.CheckResult.FAULTY
        except requests.exceptions.ConnectionError:
            return checkerlib.CheckResult.DOWN
        if not req.status_code == 200:
            logging.error("Could not register account with credentials: %s %s. Got response %d", account_name, password,
                          req.status_code)
            return func(*args, **kwargs)
        s = requests.Session()
        try:
            req = s.post(self.url() + "/login", data=payload, timeout=TIMEOUT)
        except requests.exceptions.Timeout:
            logging.error(f"Timeout trying to register admin")
            return checkerlib.CheckResult.FAULTY
        except requests.exceptions.ConnectionError:
            return checkerlib.CheckResult.DOWN
        if not req.status_code == 200:
            logging.error("Could not login account with credentials: %s %s. Got resonse %d", account_name, password,
                          req.status_code)
            return func(*args, **kwargs)
        else:
            kwargs["s"] = s
        res = func(*args, **kwargs)
        s.close()
        return res

    return wrapper


class TemplateChecker(checkerlib.BaseChecker):

    def url(self):
        return "http://[" + self.ip + "]:5000"

    @login_needed
    def place_flag(self, tick, s=None):
        # TODO remove old flag and remove "under_review" for all jokes that got enough likes
        if not s:
            return checkerlib.CheckResult.FAULTY
        flag_id = secrets.token_hex(8)
        checkerlib.store_state(str(tick), flag_id)
        flag = checkerlib.get_flag(tick)
        message = {
            "action": f"rv = submit_draft(\"{flag_id}\", \"{flag}\")",
            "team": self.team
        }
        json_data = json.dumps(message)
        payload = {
            "message": json_data,
            "hash": sign(json_data).hex()
        }
        try:
            req = s.post(self.url() + "/profile", data=payload, timeout=TIMEOUT)
        except requests.exceptions.Timeout:
            logging.error(f"Timeout trying to register admin")
            return checkerlib.CheckResult.FAULTY
        except requests.exceptions.ConnectionError:
            return checkerlib.CheckResult.DOWN
        if not req.status_code == 200:
            logging.error(f"Could not place flag, http response: {req.status_code}")
            return checkerlib.CheckResult.FAULTY
        logging.info(f'Placed flag with id: {flag_id=}')
        message = {
            "action": f"rv = process_reviewed_jokes()",
            "team": self.team
        }
        json_data = json.dumps(message)
        payload = {
            "message": json_data,
            "hash": sign(json_data).hex()
        }
        try:
            req = s.post(self.url() + "/profile", data=payload, timeout=TIMEOUT)
            logging.info("Successfully processed the reviewed jokes")
        except requests.exceptions.Timeout:
            logging.error(f"Timeout trying to register admin")
            return checkerlib.CheckResult.FAULTY
        except requests.exceptions.ConnectionError:
            return checkerlib.CheckResult.DOWN
        if not req.status_code == 200:
            logging.error(f"Could not call process_reviewed_jokes(), http response: {req.status_code}")
            return checkerlib.CheckResult.FAULTY
        return checkerlib.CheckResult.OK

    def check_service(self):
        try:
            if not self._check_admin():
                return checkerlib.CheckResult.FAULTY
            res = self._check_register_and_login()
            if res != checkerlib.CheckResult.OK:
                return res
            res = self._check_submit()
            return res
        except ConnectionError:
            return checkerlib.CheckResult.DOWN

    def _check_admin(self):
        payload = {
            'name': "admin",
            'password': "admin"
        }
        try:
            req = requests.post(self.url() + "/register", data=payload, timeout=TIMEOUT)
        except requests.exceptions.Timeout:
            logging.error(f"Timeout trying to register admin")
            return checkerlib.CheckResult.FAULTY
        except ConnectionError:
            return checkerlib.CheckResult.DOWN
        if req.status_code != 409:  # should not be possible to add account with name admin
            logging.error(f"Trying to add admin account, got response code {req.status_code}")
            return False
        logging.info("Admin check successful")
        return True

    def _check_register_and_login(self):
        successful_register = False
        payload = dict()
        for i in range(2):
            payload = _get_random_credentials()
            try:
                req = requests.post(self.url() + "/register", data=payload, timeout=TIMEOUT)
                if req.status_code == 409:
                    continue
                elif req.status_code == 200:
                    successful_register = True
                    break
            except requests.exceptions.Timeout:
                logging.error(f"Timeout trying to register admin")
                return checkerlib.CheckResult.FAULTY
            except ConnectionError:
                return checkerlib.CheckResult.DOWN
        if not successful_register:
            logging.error("Tried 5 times to register account. Still failed")
            return checkerlib.CheckResult.FAULTY
        try:
            req = requests.post(self.url() + '/login', data=payload, timeout=TIMEOUT)
            if req.status_code != 200:
                logging.error("Failed login with credentials that were recently registered")
                return checkerlib.CheckResult.FAULTY
        except requests.exceptions.Timeout:
            logging.error(f"Timeout trying to register admin")
            return checkerlib.CheckResult.FAULTY
        except ConnectionError:
            return checkerlib.CheckResult.DOWN
        logging.info("Check register + login successful")
        return checkerlib.CheckResult.OK

    @login_needed
    def _check_submit(self, s=None):
        if not s:
            return checkerlib.CheckResult.FAULTY
        random_message = utils.generate_message()
        payload = {
            "category": random.choice(service.categories.category_list),
            "content": random_message,
            "privileges": "public",
            "event": "submit",
        }
        try:
            req = s.post(self.url() + "/profile", data=payload, timeout=TIMEOUT)
            if req.status_code != 200:
                logging.error(f"Submitting joke failed with code {req.status_code} and payload:\n{payload}")
                return checkerlib.CheckResult.FAULTY
            req = s.get(self.url() + "/review", timeout=TIMEOUT)
            if random_message not in req.text:  # todo maybe check if error is due to overfilled dict but should be very unlikely
                logging.error("Submitted joke is not shown in review")
                return checkerlib.CheckResult.FAULTY
        except requests.exceptions.Timeout:
            logging.error(f"Timeout trying to register admin")
            return checkerlib.CheckResult.FAULTY
        except ConnectionError:
            return checkerlib.CheckResult.DOWN
        return checkerlib.CheckResult.OK

    @login_needed
    def check_flag(self, tick, s=None):
        if not s:
            return checkerlib.CheckResult.FAULTY
        flag = checkerlib.get_flag(tick)
        flag_id = checkerlib.load_state(str(tick))
        message = {
            "action": "rv = query_jokes(True)",
            "team": self.team
        }
        json_data = json.dumps(message)
        payload = {
            "message": json_data,
            "hash": sign(json_data).hex()
        }
        try:
            req = s.post(self.url() + "/profile", data=payload, timeout=TIMEOUT)
            if req.status_code != 200:
                logging.error(f"Tried to get via query_jokes(True) function. Got response{req.status_code}")
                return checkerlib.CheckResult.FAULTY
            if flag not in req.text:
                logging.error(f"Flag could not be found in response")
                return checkerlib.CheckResult.FLAG_NOT_FOUND
        except requests.exceptions.Timeout:
            return checkerlib.CheckResult.FAULTY
        except ConnectionError:
            return checkerlib.CheckResult.DOWN
        logging.info("Check flag successful")
        return checkerlib.CheckResult.OK


if __name__ == '__main__':
    checkerlib.run_check(TemplateChecker)
