import requests
import hashlib
import sys


def req_api_data(char):
    url = 'https://api.pwnedpasswords.com/range/' + char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching API: {res.status_code}')
    return res


def get_leaks(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    sha1pass = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first_5, tail = sha1pass[:5], sha1pass[5:]
    response = req_api_data(first_5)
    return get_leaks(response, tail)


def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(
                f'\n{password} was found {count} times, you should probably change it\n'
            )
        else:
            print(f'\n{password} not found, you\'re good to go!\n')
    return 'done'


main(sys.argv[1:])