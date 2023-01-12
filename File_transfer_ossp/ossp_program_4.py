# -*- coding: utf-8 -*-
import sys
from PyQt5.QtWidgets import *
from PyQt5 import uic, QtCore, QtGui, QtWidgets
import os
import time
from PyQt5.QtGui import *
import http.server
import html
import socketserver
import random
import os
import socket
import sys
import shutil
from shutil import make_archive
import pathlib
import signal
import platform
import argparse
import urllib.request
import urllib.parse
import urllib.error
import re
from io import BytesIO
import qrcode
import base64

import ftplib
from ftplib import FTP
from ftplib import error_perm

MacOS = "Darwin"
Linux = "Linux"
Windows = "Windows"
operating_system = platform.system()
message = """
╭──────────────────────────────────────────────────────────────────╮
│ This port is being used. Try another port.                       │
│ If you are very sure that this port is NOT in use,               │
│ then try running this script again because there is known issue  │
│ where an error is thrown even though the port is not being used. │
│ This will be fixed very soon.                                    │
│                                                                  │
│ - Developers of qr-filetrasfer                                   │
╰──────────────────────────────────────────────────────────────────╯
"""

def cursor(status):
    """
    Enable and disable the cursor in the terminal

    Keyword Arguments:
    status    --  Boolean value for the status of the cursor
    """
    if operating_system != Windows:
        print("\033[?25" + ("h" if status else "l"), end="")


def clean_exit():
    """
    These are some things that need to be done before exiting so that the user
    does have any problems after they have run qr-filetransfer
    """

    # Enable the cursor
    cursor(True)

    # Returning the cursor to home...
    print("\r", end="")

    # ...and printing "nothing" over it to hide ^C when
    # CTRL+C is pressed
    print("  ")

    sys.exit()


def FileTransferServerHandlerClass(file_name, auth, debug, no_force_download):
    """Generate Handler class.

    Args:
        file_name (str): File name to serve.
        auth: Basic auth in a base64 string or None.
        debug (bool): True to enable debug, else False.
        no_force_download (bool): If True, allow Content-Type to autodetect based
            on file name extension, else force Content-Type to
            'application/octect-stream'.

    Returns:
        FileTransferServerHandler class.
    """
    class FileTransferServerHandler(http.server.SimpleHTTPRequestHandler):
        _file_name = file_name
        _auth = auth
        _debug = debug
        _no_force_download = no_force_download

        def do_AUTHHEAD(self):
            self.send_response(401)
            self.send_header('WWW-Authenticate', 'Basic realm=\"qr-filetransfer\"')
            self.send_header('Content-type', 'text/html')
            self.end_headers()

        def do_GET(self):
            if self._auth is not None:
                # The authorization output will contain the prefix Basic, we should add it for comparing.
                if self.headers.get('Authorization') != 'Basic ' + (self._auth.decode()):
                    self.do_AUTHHEAD()
                    return

            # the self.path will start by '/', we truncate it.
            request_path = self.path[1:]
            if request_path != self._file_name:
                # access denied
                self.send_error(403)
            else:
                try:
                    super().do_GET()
                except (ConnectionResetError, ConnectionAbortedError):
                    pass

        def guess_type(self, path):
            """Add ability to force download of files.

            Args:
                path: File path to serve.

            Returns:
                Content-Type as a string.
            """
            if not self._no_force_download:
                return "application/octet-stream"

            return super().guess_type(path)

        def log_message(self, format, *args):
            if self._debug:
                super().log_message(format, *args)

    return FileTransferServerHandler


def FileUploadServerHandlerClass(output_dir, auth, debug):

    class FileUploadServerHandler(http.server.BaseHTTPRequestHandler):
        absolute_path = os.path.abspath(output_dir)
        # Making the path look nicer
        # /User/Jeff/Downloads --> ~/Downloads
        home = os.path.expanduser("~")
        nice_path = absolute_path.replace(home, "~")
        _output_dir = output_dir
        _auth = auth
        _debug = debug

        def do_AUTHHEAD(self):
            self.send_response(401)
            self.send_header('WWW-Authenticate', 'Basic realm=\"qr-filetransfer\"')
            self.send_header('Content-type', 'text/html')
            self.end_headers()

        def do_GET(self):
            if self._auth is not None:
                # The authorization output will contain the prefix Basic, we should add it for comparing.
                if self.headers.get('Authorization') != 'Basic ' + (self._auth.decode()):
                    self.do_AUTHHEAD()
                    return

            f = self.send_head()
            if f:
                self.copyfile(f, self.wfile)
                f.close()


        def do_HEAD(self):
            f = self.send_head()
            if f:
                f.close()


        def do_POST(self):
            """Serve a POST request."""
            # First, we save the post data
            r, info = self.deal_post_data()
            print((r, info, "by: ", self.client_address))

            # And write the response web page
            f = BytesIO()
            f.write(b"<!DOCTYPE html PUBLIC \"-//W3C//DTD HTML 3.2 Final//EN\"><html>")
            f.write(b"<title>qr-filetransfer</title>")
            f.write(b"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">")
            f.write(b"<link href=\"https://fonts.googleapis.com/css?family=Comfortaa\" rel=\"stylesheet\">")
            f.write(b"<link rel=\"icon\" href=\"https://raw.githubusercontent.com/sdushantha/qr-filetransfer/master/logo.png\" type=\"image/png\">")
            f.write(b"<center>")
            f.write(b"<body>")
            f.write(b"<h2 style=\"font-family: 'Comfortaa', cursive;color:'#263238';\">Upload Result Page</h2>")
            f.write(b"<hr>")

            if r:
                f.write(b"<strong style=\"font-family: 'Comfortaa', cursive;color:'#263238';\">Success: </strong>")
            else:
                f.write(b"<strong style=\"font-family: 'Comfortaa', cursive;color:'#263238';\">Failed: </strong>")

            f.write(("<span style=\"font-family: 'Comfortaa', cursive;color:'#263238';\">%s</span><br>" % info).encode())
            f.write(("<br><a href=\"%s\" style=\"font-family: 'Comfortaa', cursive;color:'#263238';\">back</a>" % self.headers['referer']).encode())
            f.write(b"<hr><small style=\"font-family: 'Comfortaa', cursive;color:'#263238';\">Powerd By: ")
            f.write(b"<a href=\"https://github.com/sdushantha/\">")
            f.write(b"sdushantha</a> and \n")
            f.write(b"<a href=\"https://github.com/npes87184/\">")
            f.write(b"npes87184</a>, check new version at \n")
            f.write(b"<a href=\"https://pypi.org/project/qr-filetransfer/\">")
            f.write(b"here</a>.</small></body>\n</html>\n")
            length = f.tell()
            f.seek(0)
            self.send_response(200)
            self.send_header("Content-type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(length))
            self.end_headers()
            if f:
                self.copyfile(f, self.wfile)
                f.close()

        def log_message(self, format, *args):
            if self._debug:
                super().log_message(format, *args)

        def deal_post_data(self):
            uploaded_files = []
            content_type = self.headers['content-type']
            if not content_type:
                return (False, "Content-Type header doesn't contain boundary")
            # Get the boundary for splitting files
            boundary = content_type.split("=")[1].encode()
            remainbytes = int(self.headers['content-length'])
            # Read first line, it should be boundary
            line = self.rfile.readline()
            remainbytes -= len(line)

            if boundary not in line:
                return (False, "Content NOT begin with boundary")
            while remainbytes > 0:
                line = self.rfile.readline()
                remainbytes -= len(line)
                fn = re.findall(r'Content-Disposition.*name="file"; filename="(.*)"', line.decode("utf-8", "backslashreplace"))
                if not fn:
                    return (False, "Can't find out file name...")
                file_name = fn[0]
                fn = os.path.join(self._output_dir, file_name)
                # Skip Content-Type
                line = self.rfile.readline()
                remainbytes -= len(line)
                # Skip \r\n
                line = self.rfile.readline()
                remainbytes -= len(line)
                try:
                    out = open(fn, 'wb')
                except IOError:
                    return (False, "Can't create file to write, do you have permission to write?")
                else:
                    with out:
                        preline = self.rfile.readline()
                        remainbytes -= len(preline)
                        while remainbytes > 0:
                            line = self.rfile.readline()
                            remainbytes -= len(line)
                            if boundary in line:
                                # Meets boundary, this file finished. We remove \r\n because of \r\n is introduced by protocol
                                preline = preline[0:-1]
                                if preline.endswith(b'\r'):
                                    preline = preline[0:-1]
                                out.write(preline)
                                uploaded_files.append(os.path.join(self.nice_path, file_name))
                                break
                            else:
                                # If not boundary, write it to output file directly.
                                out.write(preline)
                                preline = line
            return (True, "File '%s' upload success!" % ",".join(uploaded_files))


        def send_head(self):
            f = BytesIO()
            displaypath = html.escape(urllib.parse.unquote(self.nice_path))

            f.write(b"<title>qr-filetransfer</title>")
            f.write(b"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">")
            f.write(b"<link href=\"https://fonts.googleapis.com/css?family=Comfortaa\" rel=\"stylesheet\">")
            f.write(b"<link rel=\"icon\" href=\"https://raw.githubusercontent.com/sdushantha/qr-filetransfer/master/logo.png\" type=\"image/png\">")
            f.write(b"<body>")
            f.write(b"<center>")
            f.write(b"<img src=\"https://raw.githubusercontent.com/sdushantha/qr-filetransfer/master/logo.png\">")
            f.write(("<body>\n<h2 style=\"font-family: 'Comfortaa', cursive;color:'#263238';\">Please choose file to upload to %s</h2>\n" % displaypath).encode())
            f.write(b"<hr>")
            f.write(b"<form ENCTYPE=\"multipart/form-data\" method=\"post\"><input style=\"font-family:'Comfortaa', cursive;color:'#263238';\" name=\"file\" type=\"file\" multiple/><input type=\"submit\" value=\"upload\"/></form>")
            f.write(b"</center>")
            f.write(b"</body>")
            f.write(b"</html>")

            length = f.tell()
            f.seek(0)
            self.send_response(200)
            self.send_header("Content-type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(length))
            self.end_headers()
            return f


        def copyfile(self, source, outputfile):
            shutil.copyfileobj(source, outputfile)

    return FileUploadServerHandler


def get_ssid():

    if operating_system == MacOS:
        ssid = os.popen("/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I | awk '/ SSID/ {print substr($0, index($0, $2))}'").read().strip()
        return ssid

    elif operating_system == "Linux":
        ssid = os.popen("iwgetid -r 2>/dev/null",).read().strip()
        if not ssid:
            ssid = os.popen("nmcli -t -f active,ssid dev wifi | egrep '^yes' | cut -d\\' -f2 | sed 's/yes://g' 2>/dev/null").read().strip()
        return ssid

    else:
        # List interface information and extract the SSID from Profile
        # note that if WiFi is not connected, Profile line will not be found and nothing will be returned.
        interface_info = os.popen("netsh.exe wlan show interfaces").read()
        for line in interface_info.splitlines():
            if line.strip().startswith("Profile"):
                ssid = line.split(':')[1].strip()
                return ssid


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        print("Network is unreachable")
        clean_exit()


def get_local_ips_available():
    """Get a list of all local IPv4 addresses except localhost"""
    try:
        import netifaces
        ips = []
        for iface in netifaces.interfaces():
            ips.extend([x["addr"] for x in netifaces.ifaddresses(iface).get(netifaces.AF_INET, []) if x and "addr" in x])

        localhost_ip = re.compile('^127.+$')
        return [x for x in sorted(ips) if not localhost_ip.match(x)]

    except ModuleNotFoundError:
        pass


def random_port():
    return random.randint(1024, 65535)


def print_qr_code(address):
    qr = qrcode.QRCode(version=1,
                       error_correction=qrcode.ERROR_CORRECT_L,
                       box_size=10,
                       border=4,)
    qr.add_data(address)
    qr.make()

    # print_tty() shows a better looking QR code.
    # So that's why I am using print_tty() instead
    # of print_ascii() for all operating systems
    qr.print_tty()


def start_download_server(file_path, **kwargs):
    """Start the download web server.

    This function will display a QR code to the terminal that directs a user's
    cell phone to browse to this web server.  Once connected, the web browser
    will download the file, or display the file in the browser depending on the
    options set.

    Args:
        file_path (str): The file path to serve.
        **kwargs: Keyword Arguements.

    Keyword Arguments:
        debug (bool): Indication whether to output the encoded URL to the terminal.
        custom_port (str): String indicating which custom port the user wants to use.
        ip_addr (str): The IP address to bind web server to.
        auth (str): Base64 encoded 'username:password'.
        no_force_download (bool): Allow web browser to handle the file served
            instead of forcing the browser to download it.
    """
    PORT = int(kwargs["custom_port"]) if kwargs.get("custom_port") else random_port()
    LOCAL_IP = kwargs["ip_addr"] if kwargs.get("ip_addr") else get_local_ip()
    SSID = get_ssid()
    auth = kwargs.get("auth")
    debug = kwargs.get("debug", False)

    if not os.path.exists(file_path):
        print("No such file or directory")
        clean_exit()

    # Variable to mark zip for deletion, if the user uses a folder as an argument
    delete_zip = 0
    abs_path = os.path.normpath(os.path.abspath(file_path))
    file_dir = os.path.dirname(abs_path)
    file_path = os.path.basename(abs_path)

    # change to directory which contains file
    os.chdir(file_dir)

    # Checking if given file name or path is a directory
    if os.path.isdir(file_path):
        zip_name = pathlib.PurePosixPath(file_path).name

        try:
            # Zips the directory
            path_to_zip = make_archive(zip_name, "zip", file_path)
            file_path = os.path.basename(path_to_zip)
            delete_zip = file_path
        except PermissionError:
            print("Permission denied")
            clean_exit()

    # Tweaking file_path to make a perfect url
    file_path = urllib.parse.quote(file_path)

    handler = FileTransferServerHandlerClass(
        file_path,
        auth,
        debug,
        kwargs.get("no_force_download", False)
    )
    httpd = socketserver.TCPServer(("", PORT), handler)

    # This is the url to be encoded into the QR code
    address = "http://" + str(LOCAL_IP) + ":" + str(PORT) + "/" + file_path

    print("Scan the following QR code to start downloading.")
    if SSID:
        print("Make sure that your smartphone is connected to \033[1;94m{}\033[0m".format(SSID))

    # There are many times where I just need to visit the url
    # and cant bother scaning the QR code everytime when debugging
    if debug:
        print(address)

    print_qr_code(address)

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass

    # If the user sent a directory, a zip was created
    # this deletes the first created zip
    if delete_zip != 0:
        os.remove(delete_zip)

    clean_exit()


def start_upload_server(file_path, debug, custom_port, ip_addr, auth):
    """
    Keyword Arguments:
    file_path        -- String indicating the path of the file to be uploaded
    debug            -- Boolean indication whether to output the encoded url
    custom_port      -- String indicating what custom port the user wants to use
    ip_addr          -- String indicating which IP address the user want to use
    auth             -- String indicating base64 encoded username:password
    """

    if custom_port:
        PORT = int(custom_port)
    else:
        PORT = random_port()

    if ip_addr:
        LOCAL_IP = ip_addr
    else:
        LOCAL_IP = get_local_ip()

    SSID = get_ssid()

    if not os.path.exists(file_path):
        print("No such file or directory")
        clean_exit()

    if not os.path.isdir(file_path):
        print("%s is not a folder." % file_path)
        clean_exit()

    handler = FileUploadServerHandlerClass(file_path, auth, debug)

    try:
        httpd = socketserver.TCPServer(("", PORT), handler)
    except OSError:
        print(message)
        clean_exit()

    # This is the url to be encoded into the QR code
    address = "http://" + str(LOCAL_IP) + ":" + str(PORT) + "/"

    print("Scan the following QR code to start uploading.")
    if SSID:
        print("Make sure that your smartphone is connected to \033[1;94m{}\033[0m".format(SSID))

    # There are many times where I just need to visit the url
    # and cant bother scaning the QR code everytime when debugging
    if debug:
        print(address)

    print_qr_code(address)

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass

    clean_exit()

def b64_auth(a):
    splited = a.split(':')
    if len(splited) != 2:
        msg = "The format of auth should be [username:password]"
        raise argparse.ArgumentTypeError(msg)
    return base64.b64encode(a.encode())


def main():
    if operating_system != Windows:
        # SIGSTP does not work in Windows
        # This disables CTRL+Z while the script is running
        signal.signal(signal.SIGTSTP, signal.SIG_IGN)


    parser = argparse.ArgumentParser(description="Transfer files over WiFi between your computer and your smartphone from the terminal")

    parser.add_argument('file_path', action="store", help="path that you want to transfer or store the received file.")
    parser.add_argument('--debug', '-d', action="store_true", help="show the encoded url.")
    parser.add_argument('--receive', '-r', action="store_true", help="enable upload mode, received file will be stored at given path.")
    parser.add_argument('--port', '-p', dest="port", help="use a custom port")
    parser.add_argument('--ip_addr', dest="ip_addr", choices=get_local_ips_available(), help="specify IP address")
    parser.add_argument('--auth', action="store", help="add authentication, format: username:password", type=b64_auth)
    parser.add_argument(
        "--no-force-download",
        action="store_true",
        help="Allow browser to handle the file processing instead of forcing it to download."
    )

    args = parser.parse_args()

    # For Windows, emulate support for ANSI escape sequences and clear the screen first
    if operating_system == Windows:
        import colorama
        colorama.init()
        print("\033[2J", end="")

    # We are disabling the cursor so that the output looks cleaner
    cursor(False)

    if args.receive:
        start_upload_server(file_path=args.file_path, debug=args.debug, custom_port=args.port, ip_addr=args.ip_addr, auth=args.auth)
    else:
        start_download_server(
            args.file_path,
            debug=args.debug,
            custom_port=args.port,
            ip_addr=args.ip_addr,
            auth=args.auth,
            no_force_download=args.no_force_download
        )


form_class = uic.loadUiType("ossp_test.ui")[0]

class FTPClass():
    __instance = None

    @staticmethod
    def tea():
        if not FTPClass.__instance:
            raise Exception("FTPClass를 먼저 인스턴스화 해야 합니다.")
        return FTPClass.__instance

    @staticmethod
    def reset():
        FTPClass.__instance = None

    def __init__(self, pagichacha):
        if FTPClass.__instance:
            raise Exception("인스턴스가 이미 존재합니다.")
        FTPClass.__instance = pagichacha


class LoginWindow(QtWidgets.QMainWindow, form_class):
    def __init__(self):
        super().__init__()
        self.setFixedSize(820,800)
        self.setWindowIcon(QIcon("folder_icon.png"))
        self.setupUi(self)

        self.lineEdit_5.returnPressed.connect(self.ftpConnect)
        self.pushButton.clicked.connect(self.ftpConnect)
        self.pushButton_8.clicked.connect(self.qrMode)

    def ftpConnect(self):
        global result

        HOST = self.lineEdit.text()
        ID = self.lineEdit_4.text()
        PW = self.lineEdit_5.text()
        # PORT = int(self.lineEdit_6.text())

        FTPClass.reset()
        ret = FTPClass(FTP(HOST))
        print(ret,"+++++++++++++++++ 1")

        FTPClass.tea().encoding = 'utf-8'
        result = FTPClass.tea().login(ID, PW)
        print(result)

        if result and result.split(' ')[0] == '230':
            print("로그인 성공!!")
            self.myWindow = MyWindow()
            self.myWindow.show()
            self.close()
        else:
            print("Something went wrong.")

    def qrMode(self):
            self.qrWindow = QrWindow()
            self.qrWindow.show()
            self.close()



class QrWindow(QtWidgets.QMainWindow, form_class):
    def __init__(self):
        super().__init__()

        self.local_path =  None
        self.curr_local = None
        self.setFixedSize(820,900)
        self.setWindowIcon(QIcon("folder_icon.png"))
        self.setupUi(self)

        self.populate_local()
        self.doConnections()

    def tidy_up(self):
        self.label_8.show()
        self.pushButton_12.hide()
        self.lineEdit_3.hide()
        self.label_8.setText('Ready.')

    def doConnections(self):
        self.pushButton_13.clicked.connect(self.local_enter)
        self.pushButton_14.clicked.connect(self.local_up)
        self.pushButton_9.clicked.connect(self.qr_create)

    def local_enter(self):
        self.tidy_up()
        if self.curr_local:
            try:
                os.chdir(os.path.join(self.local_path, self.curr_local))
                print(self.local_path, self.curr_local,"++++ 15")
                self.label_8.setText(self.local_path+"\'"+self.curr_local)
                self.populate_local()
                self.curr_local = None
            except:
                self.label_8.setText("파일이 아닌 폴더를 선택해 주시기 바랍니다.")
            
        else:
            self.label_8.setText("로컬 폴더 선택 후 '선택 폴더진입->' 버튼을 클릭해 주시기 바랍니다.!!")


    def local_up(self):
        self.tidy_up()
        os.chdir('..')
        self.populate_local()

 
    def stor(self):
        self.tidy_up()
        print(self.curr_local,"++++ 20")
        if self.curr_local is not None:
            try:
                r = FTPClass.tea().storbinary('STOR ' + self.curr_local, open(self.curr_local, 'rb'))
                print(r,"++++ 21")
                self.label_8.setText(r + ' ' + self.curr_local)
                self.populate_remote()
            except error_perm:
                self.label_8.setText("서버쪽 권한 관련 에러가 발생하였습니다. 권한 부분을 확인해 주시기 바랍니다.")
            except:
                self.label_8.setText("폴더가 아닌 파일을 선택해야 합니다.")
                import traceback
                traceback.print_exc()
        else:
            self.label_8.setText("로컬 사이트의 파일을 선택한 후 '=>'을 클릭해야 합니다.")


    def populate_local(self):
        self.local_path = os.getcwd() # 현재 디렉토리를 가져옴
        print(self.local_path,"++++ 1")
        self.fs_model = QtWidgets.QFileSystemModel() #파일시스템 모델의 객체 생성
        print(self.fs_model,"++++ 2")
        self.fs_model.setRootPath(self.local_path) # 현재 디렉토리를 루트로 설정
        print(self.fs_model.setRootPath(self.local_path),"++++ 3")
        self.treeView.setModel(self.fs_model) #트리뷰 설정
        print(self.treeView.setModel(self.fs_model),"++++ 4")
        self.treeView.setRootIndex(self.fs_model.index(self.local_path)) # 트리뷰의 루트를 현재 디렉토리로 지정
        print(self.treeView.setRootIndex(self.fs_model.index(self.local_path)),"++++ 5")
        print('local_path:', self.local_path)
        self.treeView.selectionModel().selectionChanged.connect(self.update_curr_local)


    def update_curr_local(self):
        self.tidy_up() # 화면 아래 레이블을 Ready로 바꿈
        try:
            index = self.treeView.selectedIndexes()[0]
            print(index,"++++ 6")
            # print(self.tree_l.selectedIndexes()[1],"++++ 6-1")
            self.curr_local = index.model().itemData(index).get(0) # 딕셔너리의 첫번째 값(선택한 폴더 또는 파일)
            print(index.model().itemData(index),"++++ 7")
            print('curr_local: ', self.curr_local)
        except:
            print("curr_local 변수에 로컬 파일이 선택되지 않았습니다.")
            self.curr_local = None
        return self.curr_local

    def qr_create(self):
            print('curr_local: ', self.curr_local)

            if operating_system != Windows:
            	signal.signal(signal.SIGTSTP, signal.SIG_IGN)
            parser = argparse.ArgumentParser(description="Transfer files over WiFi between your computer and your smartphone from the terminal")

            parser.add_argument('file_path', action="store", help="path that you want to transfer or store the received file.")
            parser.add_argument('--debug', '-d', action="store_true", help="show the encoded url.")
            parser.add_argument('--receive', '-r', action="store_true", help="enable upload mode, received file will be stored at given path.")
            parser.add_argument('--port', '-p', dest="port", help="use a custom port")
            parser.add_argument('--ip_addr', dest="ip_addr", choices=get_local_ips_available(), help="specify IP address")
            parser.add_argument('--auth', action="store", help="add authentication, format: username:password", type=b64_auth)
            parser.add_argument(
                "--no-force-download",
                action="store_true",
                help="Allow browser to handle the file processing instead of forcing it to download."
            )
            args = parser.parse_args()
            if operating_system == Windows:
                import colorama
                colorama.init()
                print("\033[2J", end="")

    # We are disabling the cursor so that the output looks cleaner
            cursor(False)

            if args.receive:
                start_upload_server(file_path=args.file_path, debug=args.debug, custom_port=args.port, ip_addr=args.ip_addr, auth=args.auth)
            else:
                start_download_server(
                    args.file_path,
                    debug=args.debug,
                    custom_port=args.port,
                    ip_addr=args.ip_addr,
                    auth=args.auth,
                    no_force_download=args.no_force_download
                )

class MyWindow(QtWidgets.QMainWindow, form_class):
    def __init__(self):
        super().__init__()
        self.local_path =  None
        self.remote_path = None
        self.curr_local = None
        self.curr_remote = None
        self.setFixedSize(820,900)
        self.setWindowIcon(QIcon("folder_icon.png"))
        self.setupUi(self)

        if result and result.split(' ')[0] == '230':
            self.textEdit_2.setText(result+"로그인 성공")
        else:
            self.textEdit_2.setText(result+"로그인 실패")

        self.populate_local()
        self.populate_remote()

        self.doConnections()

    def tidy_up(self):
        self.label_8.show()
        self.pushButton_12.hide()
        self.lineEdit_3.hide()
        self.label_8.setText('Ready.')

    def doConnections(self):
        self.pushButton_3.clicked.connect(self.retr)
        self.pushButton_2.clicked.connect(self.stor)

        # 리모트 명령
        self.pushButton_4.clicked.connect(self.rnfr_rnto)
        self.pushButton_5.clicked.connect(self.dele)
        self.pushButton_6.clicked.connect(self.rmd)
        self.pushButton_7.clicked.connect(self.mkd)
        self.pushButton_16.clicked.connect(self.remote_enter)
        self.pushButton_15.clicked.connect(self.remote_up)

        self.pushButton_13.clicked.connect(self.local_enter)
        self.pushButton_14.clicked.connect(self.local_up)


    def local_enter(self):
        self.tidy_up()
        if self.curr_local:
            try:
                os.chdir(os.path.join(self.local_path, self.curr_local))
                print(self.local_path, self.curr_local,"++++ 15")
                self.label_8.setText(self.local_path+"\'"+self.curr_local)
                self.populate_local()
                self.curr_local = None
            except:
                self.label_8.setText("폴더를 선택해 주시기 바랍니다.")
        else:
            self.label_8.setText("로컬 폴더 선택 후 '선택 폴더진입->' 버튼을 클릭해 주시기 바랍니다.!!")


    def local_up(self):
        self.tidy_up()
        os.chdir('..')
        self.populate_local()

    def mkd(self):
        self.tidy_up()
        print(self.remote_path)
        if self.remote_path is not None:
            try: self.pushButton_12.clicked.disconnect()
            except: pass
            self.pushButton_12.clicked.connect(self.apply_mkd)
            self.lineEdit_3.show()
            self.pushButton_12.show()
            self.label_8.hide()

    def apply_mkd(self):
        new_name = self.lineEdit_3.text()
        print(new_name)
        if new_name != '':
            try:
                r = FTPClass.tea().mkd(new_name)
                print(r)
                self.tidy_up()
                self.label_8.setText('새로 생성된 폴더명 : ' + r)
                self.populate_remote()
                if '550' in r: # 퍼미션 에러가 발생하면 아래 익셉션에 rsise 한다.
                    raise Exception(r)
            except Exception as e:
                self.tidy_up()
                self.label_8.setText("서버쪽 권한 관련 에러가 발생하였습니다. 권한 부분을 확인해 주시기 바랍니다.: "+ str(e))
                import traceback
                traceback.print_exc()
            except:
                self.tidy_up()
                self.label_8.setText("파일이 아닌 폴더를 선택해야 합니다.")
                import traceback
                traceback.print_exc()
        else:
            self.label_8.setText("폴더명을 입력 후 'OK' 버튼을 클릭하시기 바랍니다.")


    def rmd(self):
        self.tidy_up()
        if self.curr_remote is not None:
            try:
                r = FTPClass.tea().rmd(self.curr_remote)
                self.label_8.setText(r + ' : ' + self.curr_remote)
                self.populate_remote()
                if '550' in r:
                    raise Exception(r)
            except Exception as e:
                self.label_8.setText("서버쪽 권한 관련 에러가 발생하였습니다. (파일선택 X): "+ str(e))
                import traceback
                traceback.print_exc()
            except:
                self.label_8.setText("폴더를 선택해야 합니다.")
                import traceback
                traceback.print_exc()
        else:
            self.label_8.setText("리모트 폴더 선택 후 '폴더삭제' 버튼을 클릭해 주시기 바랍니다.")


    def dele(self):
        self.tidy_up()
        print(self.curr_remote,"++++ 23")
        curr_remote = self.update_curr_remote() #<------ 여기서  부터 다시 시작
        print(curr_remote,"++++ 24")
        curr_local = self.update_curr_local()
        print(curr_local,"++++ 25")
        if self.curr_remote is not None:
            try:
                r = FTPClass.tea().delete(self.curr_remote)
                print(r,"++++ 22")
                self.label_8.setText(r + ' : ' + self.curr_remote)
                self.populate_remote()
                if '550' in r: 
                    raise Exception(r)

            except Exception as e:
                self.label_8.setText("서버쪽 권한 에러가 발생하였습니다. (폴더선택 X): "+ str(e))
            except:
                self.label_8.setText("폴더가 아닌 파일을 선택해야 합니다.")
                import traceback
                traceback.print_exc()
        else:
            self.label_8.setText("리모트 파일 선택 후 '파일삭제' 버튼을 클릭해 주시기 바랍니다.!!")


    def remote_enter(self):
        self.tidy_up()
        if self.curr_remote:
            FTPClass.tea().cwd(os.path.join(self.remote_path, self.curr_remote))
            # print(FTPClass.tea().cwd(os.path.join(self.remote_path, self.curr_remote)))
            self.remote_path2 = FTPClass.tea().pwd()
            self.label_8.setText("현재 위치(리모트): "+self.remote_path2)
            print(self.remote_path, self.curr_remote,"++++ 16")
            self.populate_remote()
            self.curr_remote = None
        else:
            self.label_8.setText("리모트 폴더 선택 후 '폴더진입->' 버튼을 클릭해 주시기 바랍니다.")

    def remote_up(self):
        self.tidy_up()
        # Waffle.tea().cwd((os.sep).join(self.remote_path.split(os.sep)[:-1]))
        FTPClass.tea().cwd('..')
        # print(os.sep, self.remote_path,"++++ 17")
        self.remote_path2 = FTPClass.tea().pwd()
        self.label_8.setText("현재 위치(리모트): "+self.remote_path2)
        self.populate_remote()


    def rnfr_rnto(self):
        if self.curr_remote is not None:
            try: self.pushButton_12.clicked.disconnect()
            except: pass
            self.pushButton_12.clicked.connect(self.apply_rn)
            self.lineEdit_3.show()
            self.pushButton_12.show()
            self.label_8.hide()
        else:
            self.label_8.setText("리모트 사이트의 파일을 선택 하셔야 합니다.")

    def apply_rn(self):
        new_name = self.lineEdit_3.text()
        if new_name != '':
            try:
                r = FTPClass.tea().rename(self.curr_remote, new_name)
                self.tidy_up()
                self.label_8.setText(r + ': ' + new_name)
                self.populate_remote()
            except error_perm:
                self.label_8.setText("서버쪽 권한 관련 에러가 발생하였습니다. 권한 부분을 확인해 주시기 바랍니다.")
            except:
                self.label_8.setText("폴더가 아닌 파일을 선택해야 합니다.")
                import traceback
                traceback.print_exc()
        else:
            self.tidy_up()
            self.label_8.setText("리모트 파일의 변경할 이름을 입력해야 합니다.")


    def retr(self): 
        self.tidy_up()
        print(self.curr_remote,"++++ 18")
        if self.curr_remote is not None:
            try:
                r = FTPClass.tea().retrbinary('RETR' + ' ' + self.curr_remote, open(self.curr_remote, 'wb').write)
                print(r,"++++ 19")
                self.label_8.setText(r + ' ' + self.curr_remote)
            except:
                self.label_8.setText("폴더가 아닌 파일을 선택해야 합니다.")
                try:
                    os.remove(self.curr_remote)
                except:
                    pass
        else:
            self.label_8.setText("리모트 사이트의 파일을 선택한 후 '<='을 클릭하셔야 합니다.")

    def stor(self):
        self.tidy_up()
        print(self.curr_local,"++++ 20")
        if self.curr_local is not None:
            try:
                r = FTPClass.tea().storbinary('STOR ' + self.curr_local, open(self.curr_local, 'rb'))
                print(r,"++++ 21")
                self.label_8.setText(r + ' ' + self.curr_local)
                self.populate_remote()
            except error_perm:
                self.label_8.setText("서버쪽 권한 관련 에러가 발생하였습니다. 권한 부분을 확인해 주시기 바랍니다.")
            except:
                self.label_8.setText("폴더가 아닌 파일을 선택해야 합니다.")
                import traceback
                traceback.print_exc()
        else:
            self.label_8.setText("로컬 사이트의 파일을 선택한 후 '=>'을 클릭해야 합니다.")


    def populate_local(self):
        self.local_path = os.getcwd() # 현재 디렉토리를 가져옴
        print(self.local_path,"++++ 1")
        self.fs_model = QtWidgets.QFileSystemModel() #파일시스템 모델의 객체 생성
        print(self.fs_model,"++++ 2")
        self.fs_model.setRootPath(self.local_path) # 현재 디렉토리를 루트로 설정
        print(self.fs_model.setRootPath(self.local_path),"++++ 3")
        self.treeView.setModel(self.fs_model) #트리뷰 설정
        print(self.treeView.setModel(self.fs_model),"++++ 4")
        self.treeView.setRootIndex(self.fs_model.index(self.local_path)) # 트리뷰의 루트를 현재 디렉토리로 지정
        print(self.treeView.setRootIndex(self.fs_model.index(self.local_path)),"++++ 5")
        print('local_path:', self.local_path)
        self.treeView.selectionModel().selectionChanged.connect(self.update_curr_local)


    def update_curr_local(self):
        self.tidy_up() # 화면 아래 레이블을 Ready로 바꿈
        try:
            index = self.treeView.selectedIndexes()[0]
            print(index,"++++ 6")
            # print(self.tree_l.selectedIndexes()[1],"++++ 6-1")
            self.curr_local = index.model().itemData(index).get(0) # 딕셔너리의 첫번째 값(선택한 폴더 또는 파일)
            print(index.model().itemData(index),"++++ 7")
            print('curr_local: ', self.curr_local)
        except:
            print("curr_local 변수에 로컬 파일이 선택되지 않았습니다.")
            self.curr_local = None
        return self.curr_local

    def populate_remote(self):
        self.remote_path = FTPClass.tea().pwd()
        print(self.remote_path,"++++ 8")
        remote_listing = FTPClass.tea().nlst()
        print(remote_listing,"++++ 9")
        self.dir_model = QtGui.QStandardItemModel()
        print(self.dir_model,"++++ 10")
        for ls in remote_listing:
            self.dir_model.appendRow(QtGui.QStandardItem(ls))
            # print(self.dir_model.appendRow(QtGui.QStandardItem(ls)),"++++ 11")
            # print(type(self.dir_model.appendRow(QtGui.QStandardItem(ls))),"++++ 11")
        self.listView.setModel(self.dir_model)
        print(self.listView.setModel(self.dir_model),"++++ 12")
        print('remote_path: ', self.remote_path)
        self.listView.selectionModel().selectionChanged.connect(self.update_curr_remote)

    def update_curr_remote(self):
        self.tidy_up()
        try:
            index = self.listView.selectedIndexes()[0]
            print(index,"++++ 13")
            self.curr_remote = index.model().itemData(index).get(0)
            print(index.model().itemData(index),"++++ 14")
            print('curr_remote: ', self.curr_remote)
        except:
            print("curr_remote 변수에 리모트 파일이 선택되지 않았습니다.")
            self.curr_remote = None
        return self.curr_remote



            

app=QApplication(sys.argv)
window = LoginWindow()
window.show()
print("Before event loop")
app.exec_()
print("After event loop")


#QR에 대한 함수들


if __name__ == "__main__":
    main()

