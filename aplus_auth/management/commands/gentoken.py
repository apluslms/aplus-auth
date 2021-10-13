from argparse import FileType
from datetime import datetime, timedelta
import json
from pprint import pformat
import re
import sys

from django.core.management.base import BaseCommand, CommandParser

from aplus_auth import settings
from aplus_auth.payload import Payload
from aplus_auth.requests import jwt_sign


timedelta_regex = re.compile(r'((?P<days>\d+?)d)?((?P<hours>\d+?)h)?((?P<minutes>\d+?)m)?((?P<seconds>\d+?)s)?')

def parse_timedelta(time_str: str):
    parts = timedelta_regex.match(time_str)
    if not parts:
        raise ValueError("Not a valid time")
    parts = parts.groupdict()
    time_params = {}
    for name, param in parts.items():
        if param:
            time_params[name] = int(param)
    return timedelta(**time_params)


def parse_time(time_str: str):
    if time_str == "false":
        return None

    try:
        return datetime.fromisoformat(time_str)
    except:
        return parse_timedelta(time_str)


class Command(BaseCommand):
    help = "Generate an access token"

    def add_arguments(self, parser: CommandParser):
        parser.add_argument("sub", type=str, help="The client, i.e. the person/service who is to use the token")
        parser.add_argument("exp", type=parse_time, help="Expiration time: ISO date, [<days>d][<hours>h][<minutes>m][<seconds>s] or false (for no expiration date).")
        parser.add_argument("aud", type=str, nargs="?", help="Audience, i.e. the public key of the requested service. Default to self")
        parser.add_argument("-p", type=FileType('r'), default=sys.stdin, help="JSON permissions file, defaults to input through stdin")

    def handle(self, *args, **options):
        expires_in = None
        expires_at = None
        if isinstance(options["exp"], datetime):
            expires_at = options["exp"]
            expires_in = datetime.utcnow() - options["exp"]
        elif isinstance(options["exp"], timedelta):
            expires_at = datetime.utcnow() + options["exp"]
            expires_in = options["exp"]

        if "p" in options:
            try:
                options["permissions"] = json.load(options.pop("p"))
            except Exception as e:
                raise RuntimeError("Failed to load permissions json") from e

        options["exp"] = expires_at
        payload = Payload(**options)

        if payload.aud is None:
            payload.aud = settings().PUBLIC_KEY

        self.stdout.write("Payload:\n")
        self.stdout.write(pformat(payload) + "\n\n")
        if expires_in is not None:
            self.stdout.write(f"The token expires at {expires_at} (in {expires_in}).\n")
        else:
            self.stdout.write("WARNING: this token has no expiry date\n\n")
        self.stdout.write(jwt_sign(payload))
