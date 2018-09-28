import os
import time
import datetime
import logging
import shutil
import smtplib
import logging
import subprocess
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.utils import formatdate
from email import encoders

#Common
LoggerName = os.path.splitext(os.path.basename(__file__))[0]
Now = datetime.datetime.now().strftime("%Y%m%d")
TestName = "Windows 10 Smart Card Test"
HostLogFilename = r"d:\builds\keytalk\Software\Client\TestProjects\Export\{}_{}.log".format(LoggerName, Now)

#Server
# WinClientBsvrMountPoint = "Z:"
# WinClientBsvrRemoteDir = r"\\192.168.33.172\builds"
# WinClientBsvrUserName = "TestUser"
# WinClientBsvrPassword = "resept4"

#Files
WinClientBsvrMountedFilesLocation = r"\\KTCLIENT-BSVR-W\builds\keytalk\Software\Client\TestProjects\Export"
TestFileDestinationDir = r"d:\builds\keytalk\Software\Client\TestProjects\Export"

#Email
SmtpSvr = "mail01.sioux.eu"
EmailSender = "keytalk.tpm.buildserver@sioux.eu"
EmailRecepients = ["andrei.korostelev@sioux.eu", "tim.de.haas@sioux.eu"]

#SUPPORT
def _parseLogLevel(aLevelNameStr):
    for lev in [logging.CRITICAL, logging.ERROR, logging.WARNING, logging.INFO, logging.DEBUG]:
        if logging.getLevelName(lev) == aLevelNameStr:
            return lev
    raise Exception("%s is not a valid logging level" % aLevelNameStr)

def _init_logger(aLoggerName, aLogFileName, anAppName, aLogLevelStr):
    myLogger = logging.getLogger(aLoggerName)

    # log to a file and to the console
    myFileHandler = logging.FileHandler(aLogFileName)
    myFileHandler.setFormatter(logging.Formatter('%(asctime)s <' +
                                                 str(os.getpid()) +
                                                 '> [%(levelname)s] %(funcName)s: %(message)s'))
    myConsoleHandler = logging.StreamHandler()
    myConsoleHandler.setFormatter(logging.Formatter('%(asctime)s: %(message)s'))
    myLogger.addHandler(myFileHandler)
    myLogger.addHandler(myConsoleHandler)

    myLogLevelStr = _parseLogLevel(aLogLevelStr)
    myLogger.setLevel(myLogLevelStr)
    myLogger.info('******************** %s. Logging Started ********************' % anAppName)
    return myLogger
	
Logger = _init_logger(LoggerName, HostLogFilename, TestName, "DEBUG")

# def _mount(mount_point, remote_dir, username, password, logger):
    # cmd = "NET USE {0} /DELETE /YES".format(mount_point, remote_dir, password, username)
    # # don't check success since can already be unmounted
    # _run_cmd(cmd, logger)

    # cmd = "NET USE {0} {1} {2} /USER:{3}".format(mount_point, remote_dir, password, username)
    # if not _run_cmd(cmd, logger):
        # raise Exception("Cannot mount " + remote_dir)

    # # check for the mounted disk to be "really" accessible. Seems this check is needed on Windows
    # if not check_disk_accessible(mount_point, logger):
        # raise Exception("Remote drive {0} mounted successfully to {1} however {1} listing is not accessible".format(
            # remote_dir, mount_point))

    # logger.debug("Successfully mounted " + remote_dir)
	
def _logged_copy_file(source, dest, logger):
    logger.debug("Copying " + source + " to " + dest)
    shutil.copy(source, dest)
	
def _run_cmd(cmd, logger=None, timeout=None):
    if logger:
        logger.debug("Executing command: " + str(cmd))

    try:
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except Exception as e:
        if logger:
            logger.error("Failed to execute {0}. {1}".format(cmd, e))
        return False

    try:
        retval = p.wait(timeout)
    except subprocess.TimeoutExpired:
        if logger and timeout:
            logger.error("{0} timed out after {1}".format(
                cmd, format_time_delta(datetime.timedelta(seconds=timeout))))
        return False
    except Exception as e:
        if logger:
            logger.error("Failed to wait for {0}. {1}".format(cmd, e))
        return False

    if retval == 0:
        return True

    if logger:
        logger.error("{0} finished with code {1}. Stdout: {2}. Stderr: {3}".format(
            cmd, retval, p.stdout.read().decode('utf-8'), p.stderr.read().decode('utf-8')))
    return False

def _send_email(caption):
    Logger.debug("Mailing " + caption + " results to " + ", ".join(EmailRecepients))

    attachments = {HostLogFilename: 'text'}
    msg = MIMEText(caption)
    if attachments:
        msg = MIMEMultipart()
        for attachment, type in attachments.items():
            if type == 'text':
                part = MIMEText(open(attachment).read(), 'plain', 'utf-8')
            elif type == 'binary':
                part = MIMEBase('application', "octet-stream")
                part.set_payload(open(attachment, "rb").read())
                encoders.encode_base64(part)
            else:
                Logger.warning('Unknown attachment type ' + type)
                continue
            part.add_header(
                'Content-Disposition', 'attachment', filename=os.path.basename(attachment))
            msg.attach(part)

    msg['Subject'] = "[KeyTalk Smart Card Test Result] " + caption
    msg['From'] = EmailSender
    msg['To'] = ', '.join(EmailRecepients)
    msg['Date'] = formatdate()

    mySmtpSvr = smtplib.SMTP(SmtpSvr)
    mySmtpSvr.sendmail(EmailSender, EmailRecepients, msg.as_string())
    mySmtpSvr.quit()
	
def _mail_results(success):
    result_str = "Succeeded" if success else "Failed"
    caption = TestName + " " + result_str
    _send_email(caption)
	

# step 1
# def mount_bsvr_drive():
    # Logger.debug("Connecting to the client build server at " + WinClientBsvrRemoteDir)
    # _mount(WinClientBsvrMountPoint, WinClientBsvrRemoteDir, WinClientBsvrUserName, WinClientBsvrPassword, Logger)
	
# step 2
def copy_built_test_files():
    for filename in os.listdir(WinClientBsvrMountedFilesLocation):
        from_path = os.path.join(WinClientBsvrMountedFilesLocation, filename)
        if os.path.isdir(from_path):
            continue
        to_path = os.path.join(TestFileDestinationDir, filename)
        _logged_copy_file(from_path, to_path, Logger)
		
# step 3
def run_test():
    command = r"d:\builds\keytalk\Software\Client\TestProjects\Export\testlibtaclientcommon.exe -v WinSmartCardUtilTest"
    success = _run_cmd(command, Logger, 300)
    _mail_results(success)
	
#Do it
# mount_bsvr_drive()
Logger.info("Start testing")
copy_built_test_files()
run_test()
	
