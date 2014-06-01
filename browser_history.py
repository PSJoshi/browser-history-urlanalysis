#!/usr/bin/python

import re
import os
import pwd
import sqlite3
import sys
import urllib2
import platform
import subprocess
import logging.handlers
import psutil

browser_list = ['firefox','chrome','opera','ie']

#linux_browser_history_paths =[{'google-chrome':''.join([os.path.expanduser('~'),'/.config/','google-chrome/'])},

def setup_logging():
    """ set up logging"""
    logging.basicConfig(level=logging.INFO) # (level=logging.DEBUG)
    logger = logging.getLogger(__name__)

    # set up file handler
    #handler = logging.FileHandler('browser_history.log')
    handler = logging.handlers.RotatingFileHandler('browser_history.log', maxBytes=20000, backupCount=5)
    handler.setLevel(logging.INFO) # logging format
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)

    # add the handlers to the logger
    logger.addHandler(handler)
    return logger

def check_internet():
    """check if internet is accessible """
    try:
        #google server check
        response=urllib2.urlopen('http://74.125.236.151',timeout=2)
        return True
    except urllib2.URLError:
        return False

def detect_os():
    """ detect operating system"""
    if 'win' in platform.system():
        #windows
        return False
    else:
        #not windows - linux flavours
        return True


def detect_os_flavour(os_type):
    """Detect Linux flavours and return the current version"""
    if os_type:
        # linux
        try:
            return platform.linux_distribution()[0]
        except Exception, e:
            return None
    else:
        # windows
        return platform.platform()

def detect_browser(log_instance):
    "detect current browser"
    try:
        browser_result = [p.name() for p in psutil.process_iter() if p.name() in browser_list]
        if browser_list:
            return browser_list[0]
        else:
            None
    except Exception,e:
        log_instance.error("Error while getting browser information - %s"%str(e).strip(),exc_info=True)

def detect_browser_old(os_type):
    """ Detect browsers and its version"""
    # Use powershell on windows to get information about installed programs in Windows
    # use rpm -qa | grep firefox -i to get information about browsers
    browsers =[]
    if os_type:
        # linux
        for browser in browser_list:
            try:
                rpm_output=subprocess.Popen(['rpm','-qa'],stdout=subprocess.PIPE)
                grep_output=subprocess.Popen(['grep','-i','firefox'],stdin=rpm_output.stdout,stdout=subprocess.PIPE)
                output=grep_output.communicate()[0]
                browsers.append({browser:True})
            except Exception,e:
                browsers.append({browser:False})


    return browsers

def detect_user(os_flag):
    """ Detect current user"""
    # Windows
    # os.environ['USERNAME']
    # win32api.GetUserName()
    user=None
    if os_flag: # linux
        # check current user
        user=pwd.getpwuid(os.getuid())[0]
    else:
        #check current windows user
        user= os.environ['USERNAME']
    return user

def get_path_firefox(log_instance,os_type):
    """
        find 'database-places.sqlite' database path for current user
    """
    browser_history_db=None
    try:
        #linux case
        if os_type:
            firefox_dir = os.path.join(os.path.expanduser('~'), '.mozilla/firefox/')
            if os.path.exists(firefox_dir):
                #missing multiple profile support
                for folder in os.listdir(firefox_dir):
                    if folder.endswith('.default'):
                        browser_history_db = os.path.join(os.path.join(firefox_dir, folder), 'places.sqlite')
    except Exception,e:
        log_instance.error('Error while finding path of firefox history database file - %s'%str(e).strip(),exc_info=True)

    return browser_history_db

def get_path_chrome(log_instance,os_type):
    """ find database path for chrome history """
    browser_history_db=None
    try:
        if os_type:
            chrome_dir = os.path.join(os.path.expanduser('~'), '.config/google-chrome/Default/')
            if os.path.exists(chrome_dir):
                # missing multiple profile support
                browser_history_db = os.path.join(chrome_dir, 'History')
    except Exception,e:
        log_instance.error('Error while finding path of Chrome history database file - %s'%str(e).strip(),exc_info=True)

    return browser_history_db

if __name__ == '__main__':
    try:
        # setup logging
        log_instance = setup_logging()

        # get os: linux-True,Windows-False and its details
        current_os = detect_os()
        if current_os:
            log_instance.info("Detected OS - linux or its similar peers")
            os_flavour = detect_os_flavour(True)
            log_instance.info("OS details - %s"% ' ' .join(os_flavour))
            current_user = detect_user(True)
            log_instance.info("current user is %s"%current_user)
        else:
            log_instance.info("Detected OS - Windows")
            os_flavour = detect_os_flavour(True)
            log_instance.info("OS details - %s"% ' ' .join(os_flavour))
            current_user = detect_user(True)
            log_instance.info("current user is %s"%current_user)
        #detect browser
        # at the moment only first running browser is detected and its history will be analyzed for malicious urls.
        # To do - detect all running instances of  browser and analyze malicious activities
        cur_browser = detect_browser(log_instance)
        log_instance.info("current browser - %s"%cur_browser)
        #check net connectivity
        if not check_internet():
            log_instance.error("This script requires internet connectivity and it seems there are some issues in \
        reaching the internet. Kindly correct and run the script once again")
            sys.exit(1)
        firefox_db = get_path_firefox(log_instance,True)
        log_instance.info("Firefox browser history database path - %s" %firefox_db)

        chrome_db = get_path_chrome(log_instance,True)
        log_instance.info("Chrome browser history database path - %s" %chrome_db)

    except Exception,e:
        log_instance.error('An error is encountered while checking the browser history for malicious urls - %s'%str(e).strip(),exc_info=True)
        #print e
# query
#SELECT moz_places.url,datetime(moz_historyvisits.visit_date/1000000,'unixepoch','localtime') from moz_historyvisits, moz_places WHERE  moz_historyvisits.place_id=moz_places.id and datetime(moz_historyvisits.visit_date/1000000,'unixepoch','localtime')>datetime('now','-1 day','localtime') limit 5;
#SELECT moz_places.url,datetime(moz_historyvisits.visit_date/1000000,'unixepoch','localtime') from moz_historyvisits, moz_places WHERE  moz_historyvisits.place_id=moz_places.id and datetime(moz_historyvisits.visit_date/1000000,'unixepoch','localtime')>datetime('now','-1 day','localtime') order by datetime(moz_historyvisits.visit_date/1000000,'unixepoch','localtime') desc limit 100;

