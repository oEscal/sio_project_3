import asyncio
import json
import base64
import argparse
import coloredlogs, logging
import os
import random
import getpass
from utils import ProtoAlgorithm, DH_parameters, encryption, unpacking, \
    length_by_cipher, key_derivation, MAC, test_compatibility, key_derivation, \
    STATE_CONNECT, STATE_OPEN, STATE_DATA, STATE_CLOSE, STATE_KEY, \
    STATE_ALGORITHM_NEGOTIATION, STATE_DH_EXCHANGE_KEYS, LOGIN, LOGIN_FINISH, \
    AUTH_CC, AUTH_MEM, STATE_AUTH, SERVER_AUTH, skey_generate_otp, new_cc_session, \
    certificate_cc, sign_nonce_cc, verify_signature, certificate_object_from_pem, \
    load_certificates, construct_certificate_chain, validate_certificate_chain, \
    verify_signature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key

logger = logging.getLogger("root")


class ClientProtocol(asyncio.Protocol):
    """
    Client that handles a single client
    """
    def __init__(self, file_name, loop, random, cipher, mode, synthesis,
                 dh_key_size):
        """
        Default constructor
        :param file_name: Name of the file to send
        :param loop: Asyncio Loop to use
        """

        # server authentication
        self.nonce = None

        self.auth_type = None
        self.file_name = file_name
        self.loop = loop
        self.state = STATE_CONNECT  # Initial State
        self.buffer = ""  # Buffer to receive data chunks

        # cc authentication
        self.session = None

        self.current_algorithm = None
        self.dh_private_key = None
        self.dh_public_key = None
        self.shared_key = None
        self.random = random
        self.cipher = cipher
        self.mode = mode
        self.synthesis = synthesis
        self.iterations_per_key = None
        self.iteration_counter = 0
        self.changing_key = False
        self.file_padding = 0
        self.dh_key_size = dh_key_size

        # algorithms
        self.AVAILABLE_CIPHERS = [
            "ChaCha20", "AES", "TripleDES", "Blowfish", "ARC4"
        ]
        self.AVAILABLE_HASHES = ["SHA256", "SHA512", "MD5"]
        self.AVAILABLE_MODES = ["CBC", "GCM", "ECB"]

    def connection_made(self, transport) -> None:
        """
        Called when the client connects.

        :param transport: The transport stream to use for this client
        :return: No return
        """
        self.transport = transport

        logger.debug("Connected to Server")

        self.first_connection()

    def data_received(self, data: str) -> None:
        """
        Called when data is received from the server.
        Stores the data in the buffer

        :param data: The data that was received. This may not be a complete JSON message
        :return:
        """
        logger.debug("Received: {}".format(data))
        try:
            self.buffer += data.decode()
        except:
            logger.exception("Could not decode data from client")

        idx = self.buffer.find("\r\n")

        while idx >= 0:  # While there are separators
            frame = self.buffer[:idx + 2].strip()  # Extract the JSON object
            self.buffer = self.buffer[
                idx + 2:]  # Removes the JSON object from the buffer

            self.on_frame(frame)  # Process the frame
            idx = self.buffer.find("\r\n")

        if len(self.buffer) > 4096 * 1024 * 1024:  # If buffer is larger than 4M
            logger.warning("Buffer to large")
            self.buffer = ""
            self.transport.close()

    def on_frame(self, frame: str) -> None:
        """
        Processes a frame (JSON Object)

        :param frame: The JSON Object to process
        :return:
        """

        # logger.debug("Frame: {}".format(frame))
        try:
            message = json.loads(frame)
        except:
            logger.exception("Could not decode the JSON message")
            self.transport.close()
            return

        mtype = message.get("type", None)
        if mtype == "SERVER_AUTH":
            self.verify_server(message)
            return
        elif mtype == "AUTH_TYPE":
            self.accept_auth_type(message)
            return
        elif mtype == "CHALLENGE":
            self.login(message)
            return
        elif mtype == "UPDATE_CREDENTIALS":
            self.update_credentials(message)
            return
        elif mtype == "OK":  # Server replied OK. We can advance the state
            if self.state == LOGIN_FINISH:
                self.send_algorithm()
            elif self.state == STATE_ALGORITHM_NEGOTIATION:
                logger.info("Algorithm accepted from server")
                self.process_DH()

            elif self.state == STATE_OPEN:
                self.send_file(self.file_name)

            elif self.state == STATE_DATA:  # Got an OK during a message transfer.
                # Reserved for future use
                pass
            else:
                logger.warning("Ignoring message from server")
            return
        elif mtype == "ITERATIONS_PER_KEY":
            if self.state == STATE_OPEN:
                iterations_per_key = message.get("data", None)
                if iterations_per_key is not None:
                    self.iterations_per_key = iterations_per_key
                    logger.info(
                        f"Setting limit for keys rotations (iterations) : {self.iterations_per_key}"
                    )
                    self.send_file(self.file_name)
                    return

            logger.warning("Invalid State!")

        elif mtype == 'AVAILABLE_ALGORITHMS':
            
            if self.state == STATE_ALGORITHM_NEGOTIATION:
                self.chose_algorithm(message)
                return
            logger.warning("Invalid state")

        elif mtype == "DH_PUBLIC_KEY":
            if self.state == STATE_DH_EXCHANGE_KEYS:
                self.get_server_DH_key(message)
                return
            logger.warning("Invalid state")

        elif mtype == "ERROR":
            logger.warning("Got error from server: {}".format(
                message.get("message", None)))
        else:
            logger.warning("Invalid message type")

        self.transport.close()
        self.loop.stop()

    def first_connection(self):
        if self.state != STATE_CONNECT:
            logger.debug("Invalid state")
            self.transport.close()
            self.loop.stop()

        self.nonce = os.urandom(64)

        logger.info(f"First connection with the server")
        message = {
            "type": "SERVER_AUTH",
            "nonce": base64.b64encode(self.nonce).decode()
        }
        self._send(message)

        self.state = SERVER_AUTH

    def verify_server(self, message):
        if self.state != SERVER_AUTH:
            logger.debug("Invalid state")
            self.transport.close()
            self.loop.stop()

        logger.info("Verifying server")

        data = message.get("data", None)
        server_certificate = certificate_object_from_pem(
            base64.b64decode(data['certificate'].encode()))
        signed_nonce = base64.b64decode(data['sign_nonce'].encode())

        certificates = load_certificates("client_certs/")

        chain = []
        chain_completed = construct_certificate_chain(chain, server_certificate, certificates)

        if not chain_completed:
            error_message = "Couldn't complete the certificate chain"
            logger.warning(error_message)
            message = {
                "type": "ERROR",
                "message": error_message
            }
            self._send(message)
            self.transport.close()
            self.loop.stop()
        else:
            valid_chain, error_messages = validate_certificate_chain(chain)

            if not valid_chain:
                logger.error(error_messages)
                message = {
                    "type": "ERROR",
                    "message": error_messages
                }
                self._send(message)
                self.transport.close()
                self.loop.stop()
            else:
                if verify_signature(server_certificate, signed_nonce, self.nonce):
                    message = {
                        "type": "SUCCESS_AUTH"
                    }
                    self._send(message)

        self.state = STATE_AUTH

    def accept_auth_type(self, message):
        if self.state != STATE_AUTH:
            logger.debug("Invalid state")
            self.transport.close()
            self.loop.stop()

        self.auth_type = message.get("auth_type", None)

        message = {
            "type": "AUTH_TYPE"
        }
        if self.auth_type == AUTH_MEM:
            message["user"] = input("User name: ")

        self._send(message)
        self.state = LOGIN

    def update_credentials(self, message):
        if self.state != LOGIN:
            logger.debug("Invalid state")
            self.transport.close()
            self.loop.stop()

        logger.info("Creating new credentials")

        password = getpass.getpass()

        data = message.get("data", None)
        new_root = base64.b64decode(data['root'].encode())
        new_index = data['index']

        otp = self.generate_new_otp(password, new_root, new_index)
        message = {
            "type": "UPDATE_CREDENTIALS",
            "otp": base64.b64encode(otp).decode()
        }
        self._send(message)


    def login(self, message):
        if self.state != LOGIN:
            logger.debug("Invalid state")
            self.transport.close()
            self.loop.stop()

        logger.info(f"Loging in")

        data = message.get("data", None)

        data_to_send = {}
        if self.auth_type == AUTH_MEM:
            index = data['index']
            root = base64.b64decode(data['root'].encode())

            password = getpass.getpass()
            otp = self.generate_new_otp(password, root, index - 1)
            data_to_send["otp"] = base64.b64encode(otp).decode()
        elif self.auth_type == AUTH_CC:
            session_success, session_data = new_cc_session()

            if not session_success:
                logger.error(f"Error establishing a new citizen card session: {session_data}")
                self.transport.close()
                self.loop.stop()
                return
            
            self.session = session_data

            nonce = base64.b64decode(data["nonce"].encode())
            data_to_send["certificate"] = base64.b64encode(certificate_cc(self.session)).decode()
            data_to_send["sign_nonce"] = base64.b64encode(sign_nonce_cc(self.session, nonce)).decode()

        message = {
            "type": "LOGIN",
            "data": data_to_send
        }  
    
        self._send(message)
        self.state = LOGIN_FINISH

    def generate_new_otp(self, password, root, index):
        password_derivation = key_derivation("SHA256", 64, password.encode())
        return skey_generate_otp(root, password_derivation, "SHA256", index)

    def process_DH(self):
        logger.info("Initializing DH")

        parameters = DH_parameters(self.dh_key_size)

        self.dh_private_key = parameters.generate_private_key()
        self.dh_public_key = self.dh_private_key.public_key()

        message = {
            "type": "PARAMETERS_AND_DH_PUBLIC_KEY",
            "data": {
                "p":
                parameters.parameter_numbers().p,
                "g":
                parameters.parameter_numbers().g,
                "key":
                self.dh_public_key.public_bytes(
                    Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode(),
            },
        }
        self._send(message)

        self.state = STATE_DH_EXCHANGE_KEYS

    def chose_algorithm(self, message):
        """Client pick an algorithm and sends to server"""
        
        algorithms = message.get('data', None)

        if algorithms is not None:
            ciphers = algorithms.get('ciphers', None)
            modes = algorithms.get('modes', None)
            hashes = algorithms.get('hashes', None)

            logger.info(f"Algorithms implemented by server : {message}")

            if ciphers is None or modes is None or hashes is None:
                logger.debug("Invalid state")
                self.transport.close()
                self.loop.stop()

            while True:
                cipher = random.SystemRandom().choice(ciphers)
                mode = random.SystemRandom().choice(modes)
                hash_al = random.SystemRandom().choice(hashes)

                if test_compatibility(cipher, mode):
                    break
                else:
                    if len(modes) == 1:
                        self.transport.close()
                        self.loop.stop()
                        logger.warning("Cipher and mode are incompatibles")
                        return
                    modes.remove(mode)

            self.current_algorithm = ProtoAlgorithm(cipher, mode, hash_al)
            logger.info(f"Chosen Algorithm {str(self.current_algorithm)}")
            message = {
                'type': 'PICKED_ALGORITHM',
                'data': self.current_algorithm.packing()
            }
            
            self._send(message)
        else:
            logger.warning("No algorithms received!")
            self.transport.close()
            self.loop.stop()

    def get_server_DH_key(self, message):
        key = message.get("key", None)
        if key is not None:
            logger.debug(f"Server DH_public_key : {key}")

            self.shared_key = key_derivation(
                self.current_algorithm.synthesis_algorithm,
                length_by_cipher[self.current_algorithm.cipher],
                self.dh_private_key.exchange(
                    load_pem_public_key(key.encode(), default_backend())),
            )

            logger.info(f"Shared Key with DH : {self.shared_key}")

        self.send_fileName()
        self.iteration_counter = 0
        self.changing_key = False

        self.state = STATE_OPEN  # Ready To send

    def send_fileName(self):
        logger.info(f"Sending file Name  to Server : {self.file_name}")
        message = {"type": "OPEN", "file_name": self.file_name}
        self._send(message)
        self.state = STATE_OPEN

    def send_algorithm(self):
        """
        Client choose a algorithm
        :param exc:
        :return:
        """
        
        if self.state != LOGIN_FINISH:
            logger.debug("Invalid state")
            self.transport.close()
            self.loop.stop()
        
        self.state = STATE_ALGORITHM_NEGOTIATION

        message = {"type": "ALGORITHM_NEGOTIATION"}

        if self.random:
            message['data'] = {
                'ciphers': self.AVAILABLE_CIPHERS,
                'modes': self.AVAILABLE_MODES,
                'hashes': self.AVAILABLE_HASHES
            }
        else:
            message['data'] = {
                'ciphers': [self.cipher],
                'modes': [self.mode],
                'hashes': [self.synthesis]
            }

        logger.debug("Sending to server client algorithms")
        logger.info(f"Client algorithms: {message['data']}")

        self._send(message)

    def connection_lost(self, exc):
        """
        Connection was lost for some reason.
        :param exc:
        :return:
        """
        logger.info("The server closed the connection")
        self.loop.stop()

    def send_file(self, file_name: str) -> None:
        """
        Sends a file to the server.
        The file is read in chunks, encoded to Base64 and sent as part of a DATA JSON message
        :param file_name: File to send
        :return:  None
        """
        logger.info("Sending file to Server...")

        with open(file_name, "rb") as f:
            message = {"type": "DATA", "data": None}
            read_size = 16 * 60
            status = True
            f.seek(self.file_padding)
            for i in range(self.iterations_per_key):
                data = f.read(read_size)

                self.file_padding += read_size

                chiper, mode = (
                    self.current_algorithm.cipher,
                    self.current_algorithm.mode,
                )

                encrypted_data, padding_length, iv, tag = encryption(
                    data, self.shared_key, chiper, mode)

                message["padding_length"] = padding_length

                message["iv"] = base64.b64encode(iv).decode()

                if tag is not None:
                    message["tag"] = base64.b64encode(tag).decode()

                h = MAC(self.shared_key,
                        self.current_algorithm.synthesis_algorithm)
                h.update(encrypted_data)

                message["MAC"] = base64.b64encode(h.finalize()).decode()
                message["data"] = base64.b64encode(encrypted_data).decode()

                self._send(message)

                if len(data) != read_size:
                    self._send({"type": "CLOSE"})
                    logger.info("File transferred. Closing transport")
                    self.transport.close()
                    return

            logger.info("Change Key")
            self.process_DH()


    def _send(self, message: str) -> None:
        """
        Effectively encodes and sends a message
        :param message:
        :return:
        """
        logger.debug("Send: {}".format(message))

        message_b = (json.dumps(message) + "\r\n").encode()
        self.transport.write(message_b)


def main():
    parser = argparse.ArgumentParser(description="Sends files to servers.")
    parser.add_argument("-v",
                        action="count",
                        dest="verbose",
                        help="Shows debug messages",
                        default=0)
    parser.add_argument(
        "-s",
        type=str,
        nargs=1,
        dest="server",
        default="127.0.0.1",
        help="Server address (default=127.0.0.1)",
    )
    parser.add_argument(
        "-p",
        type=int,
        nargs=1,
        dest="port",
        default=5000,
        help="Server port (default=5000)",
    )

    parser.add_argument(type=str, dest="file_name", help="File to send")
    parser.add_argument(
        "-r",
        dest="random",
        default=False,
        help="Random algorithm generator",
        action="store_true",
    )
    parser.add_argument(
        "--cipher",
        type=str,
        dest="cipher",
        default="TripleDES",
        help="Cipher algorithm",
    )
    parser.add_argument("--mode",
                        type=str,
                        dest="mode",
                        default="CBC",
                        help="Mode algorithm (default CBC)")
    parser.add_argument(
        "--synthesis",
        type=str,
        dest="synthesis",
        default="SHA512",
        help="Synthesis algorithm (default SHA512)",
    )
    parser.add_argument(
        "--dh_key_size",
        type=int,
        dest="dh_key_size",
        default=1024,
        required=False,
        help="DH generator key size (default 1024)",
    )

    args = parser.parse_args()
    file_name = os.path.abspath(args.file_name)
    level = logging.DEBUG if args.verbose > 0 else logging.INFO
    port = args.port
    server = args.server

    coloredlogs.install(level)
    logger.setLevel(level)

   
    if args.dh_key_size >=512:
        logger.info("Sending file: {} to {}:{} LogLevel: {}".format(
            file_name, server, port, level))
        loop = asyncio.get_event_loop()
        coro = loop.create_connection(
            lambda: ClientProtocol(file_name, loop, args.random, args.cipher, args.
                                mode, args.synthesis, args.dh_key_size),
            server,
            port,
        )
        loop.run_until_complete(coro)
        loop.run_forever()
        loop.close()
    else:
        logger.info("O dh_key_size deverá ser maior ou igual a 512")


if __name__ == "__main__":
    main()
