import os
import getpass
import argparse
import csv
from utils import key_derivation, skey_generate_otp


def main(args):
    username = getpass.getuser()                # TODO -> pedir mesmo o nome (não usar o nome do utilizador do pc)
    password = getpass.getpass()

    password_derivation = key_derivation(args.password_hkdf_alg, args.password_hkdf_size, password.encode())
    root = os.urandom(args.root_size)

    otp = skey_generate_otp(root, password_derivation, args.digest_algorithm, args.number_iterations)

    # TODO -> meter isto mais bonito
    with open(f"credentials/{username}_index", "wb") as file:
        file.write(f"{args.number_iterations}".encode())
    with open(f"credentials/{username}_root", "wb") as file:
        file.write(root)
    with open(f"credentials/{username}_otp", "wb") as file:
        file.write(otp)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Create new user credentials.")

    parser.add_argument("-r", "--root_size", type=int, help="Root size (default=64)", default=64)
    parser.add_argument("-n", "--number_iterations", type=int, help="Number of OTPs (default=10000)", default=10000)
    parser.add_argument("-d", "--digest_algorithm", type=str, help="Hash algorithm to use to create OTP_n (default=SHA256)", default="SHA256")
    parser.add_argument("-p", "--password_hkdf_alg", type=str, help="Password key derivation hash algorithm (default=SHA256)", default="SHA256")
    parser.add_argument("-s", "--password_hkdf_size", type=str, help="Password key derivation hash size (default=64)", default=64)

    args = parser.parse_args()
    main(args)
