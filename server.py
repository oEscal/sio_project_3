import asyncio
import json
import base64
import argparse
import coloredlogs, logging
import re
import os
import csv
import base64
from aio_tcpserver import tcp_server
from utils import ProtoAlgorithm, unpacking, DH_parameters, DH_parametersNumbers, \
    key_derivation, length_by_cipher, decryption, MAC, \
    STATE_CONNECT, STATE_OPEN, STATE_DATA, STATE_CLOSE, STATE_ALGORITHMS, \
    STATE_ALGORITHM_ACK, STATE_DH_EXCHANGE_KEYS, LOGIN, UPDATE_CREDENTIALS, \
    LOGIN_FINISH, ACCESS_CHECKED, ACCESS_FILE, AUTH_CC, AUTH_MEM, digest, \
    verify_signature, certificate_object, construct_certificate_chain, load_certificates, \
    validate_certificate_chain
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key

logger = logging.getLogger("root")

# GLOBAL
STORAGE_DIR = "files"
ITERATIONS_PER_KEY = 100
AUTH_TYPE = AUTH_MEM

class ClientHandler(asyncio.Protocol):
    def __init__(self, signal):
        """
		Default constructor
		"""

        # for challenge with memorized key
        self.username = None
        self.current_otp = None
        self.current_otp_index = None
        self.current_otp_root = None

        # for challenge with cc
        self.nonce = None

        # for new credentials
        self.clear_credentials = False
        self.new_root = None
        self.new_index = None
        self.new_otp = None

        self.signal = signal
        self.state = 0
        self.file = None
        self.file_name = None
        self.file_path = None
        self.storage_dir = STORAGE_DIR
        self.buffer = ""
        self.peername = ""
        self.current_algorithm = None
        self.dh_private_key = None
        self.dh_public_key = None
        self.shared_key = None
        self.iterations_per_key = ITERATIONS_PER_KEY
        self.current_iteration = 0
        self.data_print = True  #variable to prevent a logger print spam

        # algorithms
        self.AVAILABLE_CIPHERS = ["ChaCha20", "AES", "TripleDES"]
        self.AVAILABLE_HASHES = ["SHA256", "SHA512", "MD5"]
        self.AVAILABLE_MODES = ["CBC", "GCM"]

    def connection_made(self, transport) -> None:
        """
		Called when a client connects

		:param transport: The transport stream to use with this client
		:return:
		"""
        self.peername = transport.get_extra_info("peername")
        logger.info("\n\nConnection from {}".format(self.peername))
        self.transport = transport
        self.state = STATE_CONNECT

    def data_received(self, data: bytes) -> None:
        """
        Called when data is received from the client.
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

        if len(self.buffer
               ) > 4096 * 1024 * 1024:  # If buffer is larger than 4M
            logger.warning("Buffer to large")
            self.buffer = ""
            self.transport.close()

    def on_frame(self, frame: str) -> None:
        """
		Called when a frame (JSON Object) is extracted

		:param frame: The JSON object to process
		:return:
		"""
        # logger.debug("Frame: {}".format(frame))

        try:
            message = json.loads(frame)
        except:
            logger.exception("Could not decode JSON message: {}".format(frame))
            self.transport.close()
            return

        print(f"{message}\n\n")

        mtype = message.get("type", "").upper()
        if mtype == "FIRST_CONNECTION":
            ret = self.send_challenge(message)
        elif mtype == "UPDATE_CREDENTIALS":
            ret = self.update_credentials(message)
        elif mtype == "LOGIN":
            ret = self.login(message)
        elif mtype == "OPEN":
            ret = self.process_open(message)
        elif mtype == "DATA":
            ret = self.process_data(message)
        elif mtype == "CLOSE":
            ret = self.process_close(message)
        elif mtype == "ALGORITHM_NEGOTIATION":
            ret = self.process_algorithm_negotiation(message)
        elif mtype == "PARAMETERS_AND_DH_PUBLIC_KEY":
            ret = self.process_DH_Public_Key(message)
        elif mtype == "PICKED_ALGORITHM":
            ret = self.process_client_algorithm_pick(message)
        else:
            logger.warning("Invalid message type: {}".format(message["type"]))
            ret = False

        if not ret:
            try:
                self._send({"type": "ERROR", "message": "See server"})
            except:
                pass  # Silently ignore

            logger.info("Closing transport")
            if self.file is not None:
                self.file.close()
                self.file = None

            self.state = STATE_CLOSE
            self.transport.close()

    def request_login_message(self):
        data = {"auth_type": AUTH_TYPE}
        
        if AUTH_TYPE == AUTH_MEM:
            data["index"] = self.current_otp_index
            data["root"] = base64.b64encode(self.current_otp_root).decode()
        elif AUTH_TYPE == AUTH_CC:
            self.nonce = os.urandom(64)
            data["nonce"] = base64.b64encode(self.nonce).decode()                                  # TODO
        
        return {
            "type": "CHALLENGE",
            "data": data
        }

    def send_challenge(self, message):
        if self.state != STATE_CONNECT:
            logger.warning("Invalid state. Discarding")
            return False

        logger.info(f"Sending challenge")

        self.state = LOGIN
        if AUTH_TYPE == AUTH_MEM:
            self.username = message.get('user', None)

            try:
                with open(f"credentials/{self.username}_index", "rb") as file:
                    self.current_otp_index = int(file.read())
                with open(f"credentials/{self.username}_root", "rb") as file:
                    self.current_otp_root = file.read()
                with open(f"credentials/{self.username}_otp", "rb") as file:
                    self.current_otp = file.read()
            except OSError as e:
                logger.error(f"Error opening the file: {e}")
                return False
            except Exception as error:
                logger.error(f"Unexpected error while reading the file: {error}")
                return False

            message = self.request_login_message()

            # TODO -> depois meter a puder escolher o número minimo
            if self.current_otp_index < 100:                            # request client to update current credentials
                logger.info("Current credentials in end of life! Requesting new ones.")

                self.new_root = os.urandom(64)
                self.new_index = 10000

                message = {
                    "type": "UPDATE_CREDENTIALS",
                    "data": {
                        "index": self.new_index,
                        "root": base64.b64encode(self.new_root).decode()
                    }
                }

                self.state = UPDATE_CREDENTIALS
        elif AUTH_TYPE == AUTH_CC:
            message = self.request_login_message()

        self._send(message)
        return True

    def update_credentials(self, message):
        if self.state != UPDATE_CREDENTIALS:
            logger.warning("Invalid State")
            return False

        logger.info(f"Creating new credentials")

        self.new_otp = base64.b64decode(message.get("otp", None).encode())
        self.clear_credentials = True                                   # if successful login -> save new credentials

        message = self.request_login_message()
        self._send(message)

        self.state = LOGIN
        return True

    def login(self, message):
        if self.state != LOGIN:
            logger.warning("Invalid State")
            return False

        logger.info(f"Loging in")

        data = message.get("data", None)

        status = False                                                  # status = False -> if login wasn't a success
        if AUTH_TYPE == AUTH_MEM:
            new_otp = base64.b64decode(data["otp"].encode())
            current_otp_client = digest(new_otp, "SHA256")                  # TODO -> METER MAIS BONITO

            message = {
                "type": "ERROR",
                "message": "Invalid credentials for logging in"
            }

            if self.current_otp == current_otp_client:                      # success login
                status = True

                if self.clear_credentials:
                    logger.info("Clearing old credentials and saving new ones.")

                    self.current_otp_index = self.new_index + 1
                    self.current_otp_root = self.new_root 
                    new_otp = self.new_otp

                with open(f"credentials/{self.username}_index", "wb") as file:
                    file.write(f"{self.current_otp_index - 1}".encode())
                with open(f"credentials/{self.username}_root", "wb") as file:
                    file.write(self.current_otp_root)
                with open(f"credentials/{self.username}_otp", "wb") as file:
                    file.write(new_otp)

                access_result = self.check_access()                         # very access
                if not access_result[0]:
                    logger.warning(access_result[1])

                    status = False
                    message = {
                        "type": "ERROR",
                        "message": access_result[1]
                    }
                else:
                    message = {
                        "type": "OK"
                    }
                    logger.info(access_result[1])

                self.state = LOGIN_FINISH

                logger.info("User logged in with success! Credentials updated.")
            else:
                logger.info("User not logged in! Wrong credentials where given.")
        elif AUTH_TYPE == AUTH_CC:
            cc_certificate = certificate_object(base64.b64decode(data["certificate"].encode()))
            signed_nonce = base64.b64decode(data["sign_nonce"].encode())

            certificates = load_certificates("cc_certificates/")                                    # TODO

            chain = []
            chain_completed = construct_certificate_chain(chain, cc_certificate, certificates)

            if not chain_completed:
                error_message = "Couldn't complete the certificate chain"
                logger.warning(error_message)
                message = {
                    "type": "ERROR",
                    "message": error_message
                }
                status = False
            else:
                valid_chain = validate_certificate_chain(chain)
                if not valid_chain:
                    error_message = "One of the chain certificates was not signed by it's issuer"
                    logger.error(error_message)
                    message = {
                        "type": "ERROR",
                        "message": error_message
                    }
                    status = False
                else:
                    status = verify_signature(cc_certificate, signed_nonce, self.nonce)

        self._send(message)
        return status

    def check_access(self):
        logger.info("Verifying access")

        with open(ACCESS_FILE, 'r') as file:
            data = json.load(file)

        if self.username not in data:
            return False, "User not in access list"
        elif not data[self.username]["send"]:
            return False, "User has not access to transfer files"
        return True, "User has access to transfer files"

    def process_client_algorithm_pick(self, message: str) -> bool:
        """
            Reads client algorithm pick
        """
        
        if self.state != STATE_ALGORITHMS:
            logger.warning("Invalid State")
            return False

        algorithm = message.get('data', None)
        if algorithm is None:
            logger.warning("Invalid algorithm")
            return False

        key_algorithm, cipher, mode, hash_al = unpacking(algorithm)

        self.current_algorithm = ProtoAlgorithm(cipher, mode, hash_al)
        logger.info(f"Algorithm picked by client: {self.current_algorithm}")

        message = {'type': 'OK'}

        self._send(message)

        self.state = STATE_ALGORITHM_ACK
        return True

    def process_DH_Public_Key(self, message: str) -> bool:
        """	
			Reads client DH_public_key,p and g parameters
			Also server creates their own DH_keys and sent public key to server
		"""
        
        if not (self.state == STATE_ALGORITHM_ACK or self.state == STATE_DATA):
            return False
        
        data = message.get("data", None)
        if data is None:
            return False

        logger.debug(f"Client DH_public_key : {data}")
        try:
            p = data.get("p", "None")
            g = data.get("g", "None")
            key = data.get("key")

            parameters = DH_parametersNumbers(p, g)

            self.dh_private_key = parameters.generate_private_key()
            self.dh_public_key = self.dh_private_key.public_key()

            message = {
                "type": "DH_PUBLIC_KEY",
                "key": self.dh_public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode(),
            }

            self._send(message)

            self.state = STATE_DH_EXCHANGE_KEYS

            self.shared_key = key_derivation(
                self.current_algorithm.synthesis_algorithm,
                length_by_cipher[self.current_algorithm.cipher],
                self.dh_private_key.exchange(
                    load_pem_public_key(key.encode(), default_backend())),
            )

            logger.info(f"Shared_key with DH : {self.shared_key}")
        except Exception as e:
            logger.warning(e)
            return False

        return True

    def process_open(self, message: str) -> bool:
        """
		Processes an OPEN message from the client
		This message should contain the filename

		:param message: The message to process
		:return: Boolean indicating the success of the operation
		"""

        if self.state != STATE_DH_EXCHANGE_KEYS:
            logger.warning("Invalid state. Discarding")
            return False

        if not "file_name" in message:
            logger.warning("No filename in Open")
            return False

        # Only chars and letters in the filename
        file_name = re.sub(r"[^\w\.]", "", message["file_name"])
        file_path = os.path.join(self.storage_dir, file_name)
        if not os.path.exists("files"):
            try:
                os.mkdir("files")
            except:
                logger.exception("Unable to create storage directory")
                return False

        try:
            if self.current_iteration == 0:
                self.file = open(file_path, "wb")
                logger.info("Process Open: {}".format(message))
        except Exception:
            logger.exception("Unable to open file")
            return False

        

        if self.current_iteration == 0:
            message = {
                "type": "ITERATIONS_PER_KEY",
                'data': self.iterations_per_key
            }
        else:
            message = {'type': "OK"}

        self._send(message)
        self.data_print = True
        self.current_iteration = 0
        self.file_name = file_name
        self.file_path = file_path
        self.state = STATE_OPEN
        return True

    def process_data(self, message: str) -> bool:
        """
		Processes a DATA message from the client
		This message should contain a chunk of the file

		:param message: The message to process
		:return: Boolean indicating the success of the operation
		"""
        if self.data_print:
            logger.info("Processing Data...")

        self.data_print = False

        if self.state == STATE_OPEN:
            self.state = STATE_DATA

        elif self.state == STATE_DATA:
            # Next packets
            pass

        else:
            logger.warning("Invalid state. Discarding")
            return False

        try:
            data = message.get("data", None)
            if data is None:
                logger.debug("Invalid message. No data found")
                return False

            self.current_iteration += 1
            if self.current_iteration >= self.iterations_per_key:
                logger.info("Changing Key")

            cipher = self.current_algorithm.cipher
            mode = self.current_algorithm.mode

            padding_length = message.get("padding_length", None)
            iv = message.get("iv", None)
            MAC_b64 = message.get("MAC", None)
            tag = message.get("tag", None)

            if padding_length is None or iv is None or MAC_b64 is None:
                return False

            iv = base64.b64decode(iv)
            encrypted_data = base64.b64decode(message["data"])
            received_MAC = base64.b64decode(MAC_b64)

            if tag is not None:
                tag = base64.b64decode(tag)

            h = MAC(self.shared_key,
                    self.current_algorithm.synthesis_algorithm)

            #TEST MAC
            #encrypted_data+=('\x00').encode()

            h.update(encrypted_data)
            current_MAC = h.finalize()

            if received_MAC != current_MAC:
                logger.warning("MAC authentication Failed")
                return False

            decrypted_data = base64.b64encode(
                decryption(
                    encrypted_data,
                    self.shared_key,
                    cipher,
                    mode,
                    padding_length,
                    iv,
                    tag,
                ))

            bdata = base64.b64decode(decrypted_data)

        except:
            logger.exception(
                "Could not decode base64 content from message.data")
            return False

        try:
            self.file.write(bdata)
            self.file.flush()
        except:
            logger.exception("Could not write to file")
            return False

        return True

    def process_close(self, message: str) -> bool:
        """
		Processes a CLOSE message from the client.
		This message will trigger the termination of this session

		:param message: The message to process
		:return: Boolean indicating the success of the operation
		"""
        logger.info("Process Close: {}".format(message))

        self.transport.close()
        if self.file is not None:
            self.file.close()
            self.file = None

        self.state = STATE_CLOSE

        return True

    def process_algorithm_negotiation(self, message: str) -> bool:
        """
		Processes an algorithm negotiation from the client

		:param message: The message to process
		:return: Boolean indicating the success of the operation
		"""
        
        if self.state != LOGIN_FINISH:
            logger.warning("Invalid state. Discarding")
            return False
        
        client_algorithms = message.get("data", None)
        logger.info(f"Client algorithms : {client_algorithms}")

        client_ciphers = client_algorithms.get('ciphers', None)
        client_modes = client_algorithms.get('modes', None)
        client_hashes = client_algorithms.get('hashes', None)

        if client_ciphers is None or client_modes is None or client_hashes is None:
            logger.warning("Invalid algorithm request!")
            return False

        common_ciphers = list(
            set(client_ciphers).intersection(set(self.AVAILABLE_CIPHERS)))
        common_modes = list(
            set(client_modes).intersection(set(self.AVAILABLE_MODES)))
        common_hashes = list(
            set(client_hashes).intersection(set(self.AVAILABLE_HASHES)))

        if common_ciphers == [] or common_modes == [] or common_hashes == []:
            logger.warning("Invalid algorithm request!")
            return False

        message = {
            'type': 'AVAILABLE_ALGORITHMS',
            'data': {
                'ciphers': common_ciphers,
                'modes': common_modes,
                'hashes': common_hashes
            }
        }

        self._send(message)
        self.state = STATE_ALGORITHMS
        
        return True

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
    global STORAGE_DIR
    global ITERATIONS_PER_KEY
    global AUTH_TYPE

    parser = argparse.ArgumentParser(
        description="Receives files from clients.")
    parser.add_argument(
        "-v",
        action="count",
        dest="verbose",
        help="Shows debug messages (default=False)",
        default=0,
    )
    parser.add_argument(
        "-p",
        type=int,
        nargs=1,
        dest="port",
        default=5000,
        help="TCP Port to use (default=5000)",
    )

    parser.add_argument(
        "-d",
        type=str,
        required=False,
        dest="storage_dir",
        default="files",
        help="Where to store files (default=./files)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        required=False,
        dest="limit",
        default=100,
        help="Limit to make key rotation (number iterations) (default 100)")

    parser.add_argument(
        "--authentication",
        type=str,
        required=False,
        choices=[AUTH_MEM, AUTH_CC],
        default=AUTH_MEM,
        help="Choose authentication method to use"
    )

    args = parser.parse_args()

    STORAGE_DIR = os.path.abspath(args.storage_dir)
    ITERATIONS_PER_KEY = args.limit
    AUTH_TYPE = args.authentication

    level = logging.DEBUG if args.verbose > 0 else logging.INFO
    port = args.port
    if port <= 0 or port > 65535:
        logger.error("Invalid port")
        return

    if port < 1024 and not os.geteuid() == 0:
        logger.error("Ports below 1024 require eUID=0 (root)")
        return

    coloredlogs.install(level)
    logger.setLevel(level)

    logger.info("Port: {} LogLevel: {} Storage: {}".format(
        port, level, STORAGE_DIR))
    tcp_server(ClientHandler, worker=2, port=port, reuse_port=True)


if __name__ == "__main__":
    main()
