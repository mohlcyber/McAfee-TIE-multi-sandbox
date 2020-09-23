#!/usr/bin/env python3.7
# Written by mohlcyber 31/10/2019 v.0.1

import os
import sys
import ssl
import base64
import json
import secrets
import cgi
import socket
import threading
import time
import hashlib
import logging

from lastline import LASTLINE
from atd import ATD
from vmray_sandbox import VMRAY

from http.server import HTTPServer, BaseHTTPRequestHandler

from dotenv import load_dotenv

load_dotenv(verbose=True)


DEFAULT_LOG_LEVEL = "INFO"

CREDS = base64.b64encode((os.getenv("TIE_USER") + ":" + os.getenv("TIE_PW")).encode())

SESSION_TOKEN = secrets.token_hex(13)
SESSION_USER_ID = "1"
SESSION_CREDS = base64.b64encode((SESSION_TOKEN + ":" + SESSION_USER_ID).encode())


class Handler(BaseHTTPRequestHandler):
    def do_AUTHHEAD(self):
        self.send_response(401)
        self.send_header("VE-SDK-API", 'Basic realm="TOKEN"')
        self.send_header("Content-type", "application/json")
        self.end_headers()

    def do_GET(self):
        if self.path == "/php/session.php":
            if self.headers.get("VE-SDK-API"):
                if self.headers.get("VE-SDK-API") == CREDS.decode():
                    self.send_response(200)
                    self.send_header("Content-type", "application/json")
                    self.end_headers()
                    payload = {
                        "success": True,
                        "results": {
                            "session": SESSION_TOKEN,
                            "userId": "1",
                            "isAdmin": "1",
                            "serverTZ": "CEST",
                            "apiVersion": "1.5.0",
                            "matdVersion": "4.6.2.13",
                        },
                    }

                    self.wfile.write(json.dumps(payload).encode())
                    pass
                else:
                    self.do_AUTHHEAD()
                    self.wfile.write(
                        "ERROR: {0} not authenticated".format(
                            self.headers.get("VE-SDK-API")
                        ).encode()
                    )
                    pass
            else:
                self.do_AUTHHEAD()
                self.wfile.write("ERROR: No auth header received".encode())
                pass
        else:
            self.do_AUTHHEAD()
            self.wfile.write("ERROR: Wrong path to authenticate".encode())
            pass

    def do_POST(self):
        content_length = int(self.headers["Content-Length"])
        if self.headers.get("VE-SDK-API") == SESSION_CREDS.decode():
            self.send_response(200)
            self.end_headers()

            form = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                environ={
                    "REQUEST_METHOD": "POST",
                    "CONTENT_TYPE": self.headers["Content-Type"],
                },
            )
            filename = "SAMPLE"
            for item in form.list:
                if item.filename:
                    filename = item.filename

            data = form.getvalue("amas_filename")
            open(filename, "wb").write(data)

            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.send_header("Content-length", content_length)

            md5 = hashlib.md5(data).hexdigest()
            sha1 = hashlib.sha1(data).hexdigest()
            sha256 = hashlib.sha256(data).hexdigest()
            size = os.path.getsize(filename)

            os.remove(filename)

            payload = {
                "success": True,
                "subId": 123456789,
                "mimeType": "application/x-dosexec",
                "fileId": "",
                "filesWait": 0,
                "estimatedTime": 0,
                "results": [
                    {
                        "taskId": 123456789,
                        "messageId": "",
                        "file": filename,
                        "submitType": "0",
                        "url": "",
                        "destIp": None,
                        "srcIp": "",
                        "md5": md5,
                        "sha1": sha1,
                        "sha256": sha256,
                        "size": size,
                        "cache": 0,
                    }
                ],
            }

            self.wfile.write(json.dumps(payload).encode())
            self.end_headers()
            pass

            # Multi Sandbox Submission
            thread_list = []
            sandboxes = []
            if os.getenv("ATD_ENABLED") == "true":
                sandboxes.append(ATD)
            if os.getenv("LASTLINE_ENABLED") == "true":
                sandboxes.append(LASTLINE)
            if os.getenv("VMRAY_ENABLED") == "true":
                sandboxes.append(VMRAY)

            for sandbox in sandboxes:
                thread = threading.Thread(
                    target=self.multi_sandbox,
                    args=(
                        sandbox,
                        filename,
                        data,
                    ),
                )
                thread_list.append(thread)
                thread.start()

            # Optional if you want to wait until the threads are done.
            # for thread in thread_list:
            #     thread.join()

        else:
            self.do_AUTHHEAD()
            self.wfile.write(
                "ERROR: {0} not authenticated".format(
                    self.headers.get("VE-SDK-API")
                ).encode()
            )
            pass

    def do_DELETE(self):
        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        self.wfile.write("SUCCESS: Logout".encode())

    def multi_sandbox(self, module, filename, data):
        module(filename, data).run()


class Thread(threading.Thread):
    def __init__(self, i):
        threading.Thread.__init__(self)
        self.i = i
        self.daemon = True
        self.start()

    def run(self):
        httpd = HTTPServer(addr, Handler, False)
        httpd.socket = sock
        httpd.server_bind = self.server_close = lambda self: None
        httpd.serve_forever()


if __name__ == "__main__":
    # initialize the logger
    log_level = os.getenv("LOG_LEVEL")
    if log_level is None:
        log_level = DEFAULT_LOG_LEVEL
    logging.getLogger().setLevel(level=logging.getLevelName(log_level))
    formatter = logging.Formatter(
        fmt="%(asctime)s.%(msecs)03d [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    logging.getLogger().addHandler(stream_handler)
    file_handler = logging.FileHandler(os.getenv("LOG_FILE_PATH"))
    file_handler.setFormatter(formatter)
    logging.getLogger().addHandler(file_handler)

    # set up the server
    addr = ("", int(os.getenv("TIE_FILE_RETRIEVER_PORT")))
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(addr)
    sock.listen(5)
    sock = ssl.wrap_socket(
        sock,
        keyfile=os.getenv("TIE_KEY_PATH"),
        certfile=os.getenv("TIE_CERTIFICATE_PATH"),
        server_side=True,
    )
    logging.info("TIE File Retriever server has been started")

    for i in range(10):
        Thread(i)

    while True:
        time.sleep(9e7)
