import sqlite3
import os
import sys
import re
import ConfigParser
import base64
import gconf
from ctypes import *
import struct

libnss = CDLL("libnss3.so")

#Password structures
class SECItem(Structure):
    _fields_ = [('type',c_uint),('data',c_void_p),('len',c_uint)]
		
class secuPWData(Structure):
    _fields_ = [('source',c_ubyte),('data',c_char_p)]

(SECWouldBlock,SECFailure,SECSuccess)=(-2,-1,0)
(PW_NONE,PW_FROMFILE,PW_PLAINTEXT,PW_EXTERNAL)=(0,1,2,3)

pwdata = secuPWData()
pwdata.source = PW_NONE
pwdata.data=0

uname = SECItem()
passwd = SECItem()
dectext = SECItem()
enctext = SECItem()
keyid = SECItem()

class Context(object):
    def __init__(self, path):
        libnss.NSS_Init(path)

    def decript(self, userdata, passdata):
        uname.data  = cast(c_char_p(userdata),c_void_p)
        uname.len = len(userdata)
        passwd.data = cast(c_char_p(passdata),c_void_p)
        passwd.len=len(passdata)

        libnss.PK11SDR_Decrypt(byref(uname),byref(dectext),byref(pwdata))
        username = string_at(dectext.data,dectext.len)

        libnss.PK11SDR_Decrypt(byref(passwd),byref(dectext),byref(pwdata))
        password = string_at(dectext.data,dectext.len)

        return (username, password)

    def encript(self, user, pwd):
        keyid.len = 0;
        
        uname.data  = cast(c_char_p(user),c_void_p)
        uname.len = len(user)

        passwd.data = cast(c_char_p(pwd),c_void_p)
        passwd.len=len(pwd)

        libnss.PK11SDR_Encrypt(byref(keyid), byref(uname), byref(enctext), byref(pwdata))
        userenc = string_at(enctext.data, enctext.len)

        libnss.PK11SDR_Encrypt(byref(keyid), byref(passwd), byref(enctext), byref(pwdata))
        pwdenc = string_at(enctext.data, enctext.len)

        return (userenc, pwdenc)

def get_firefox_profile():
    path = os.path.expanduser('~/.mozilla/firefox/profiles.ini')
    
    if not os.path.exists(path):
        return

    config = ConfigParser.ConfigParser()
    config.readfp(open(path))

    for section in config.sections():
        if not config.has_option(section, 'name'):
            continue

        name = config.get(section, 'name')
        if name != 'default':
            continue

        return os.path.join(os.path.expanduser('~/.mozilla/firefox'),
                            config.get(section, 'path'))

class Password(object):
    def __init__(self, manager, hostname, realm,
                 username, password):
        self.manager = manager
        self.hostname = hostname
        self.realm = realm
        self.username = username
        self.password = password

    @property
    def encripted(self):
        user, pwd = self.manager.context.encript(self.username,
                                                 self.password)

        return (base64.b64encode(user),
                base64.b64encode(pwd))
    @property
    def decripted(self):
        userdata = base64.b64decode(self.username)
        passdata = base64.b64decode(self.password)

        return self.manager.context.decript(userdata,
                                            passdata)

class FirefoxPasswordManager(object):
    def __init__(self, profile_path):
        self.profile_path = profile_path
        self.context = Context(profile_path)

    @property
    def signons_path(self):
        return os.path.join(self.profile_path,
                            'signons.sqlite')

    def read_passwords(self):
        conn = sqlite3.connect(self.signons_path)
        cur = conn.cursor()

        cur.execute('select hostname, httpRealm, '
                    'encryptedUsername, encryptedPassword'
                    ' from moz_logins')
        
        for row in cur:
            yield Password(self, *row)

    def clean_passwords(self):
        conn = sqlite3.connect(self.signons_path)
        cur = conn.cursor()

        cur.execute('delete from moz_logins')

        conn.commit()

    def insert_password(self, p):
        conn = sqlite3.connect(self.signons_path)
        cur = conn.cursor()


        user, pwd = p.encripted
        cur.execute('INSERT INTO moz_logins (hostname, httpRealm, '
                    'usernameField, passwordField, '
                    'encryptedUsername, encryptedPassword) '
                    'VALUES (?, ?, ?, ?, ?, ?)', (p.hostname, p.realm,
                                                  '', '',
                                                  user, pwd))

        conn.commit()
                                            

def get_proxy_settings():
    g_client = gconf.client_get_default()
    
    if not g_client.get_bool('/system/http_proxy/use_http_proxy'):
        return

    ctx = {'host': g_client.get_string('/system/http_proxy/host'),
           'port': g_client.get_int('/system/http_proxy/port')
           }

    if g_client.get_bool('/system/http_proxy/use_authentication'):
        ctx.update({
                'user': g_client.get_string('/system/http_proxy/authentication_user'),
                'passwd': g_client.get_string('/system/http_proxy/authentication_password')})

    return ctx

class FirefoxPrefs(object):
    def __init__(self, profile_path):
        self.profile_path = profile_path
        
        self.path = os.path.join(profile_path,
                                 'prefs.js')
        
        self.context = ""
        if os.path.exists(self.path):
            self.content = open(self.path, 'rw').read()

    def set_bool(self, key, value):
        fe = re.search(r'user_pref\("%s", (?P<value>true|false)\);' % key, self.content)
        raw_value = 'true' if value else 'false'

        if fe:
            raw_salved_value = fe.group('value') 
            salved_value = True if raw_salved_value == 'true' else False

            if salved_value == value:
                return

            self.content = self.content.replace('user_pref("%s", %s);' % (key, raw_salved_value),
                                                'user_pref("%s", %s);' % (key, raw_value))
        else:
            row = 'user_pref("%s", %s);' % (key, raw_value)

            if self.content[-1] != '\n':
                self.content += '\n%s' % row
            else:
                self.content += row

    def save(self):
        fp = open(self.path, 'w')
        fp.write(self.content)
        fp.close()

if __name__ == "__main__":
    
    profile_path = get_firefox_profile()
    proxy_settings = get_proxy_settings()
    
    
    if profile_path:
        pm = FirefoxPasswordManager(profile_path)
        fp = FirefoxPrefs(profile_path)
        fp.set_bool("signon.autologin.proxy", True)
        fp.save()

        pm.clean_passwords()

        if proxy_settings:
            hostname = "moz-proxy://%s:%d" % (proxy_settings['host'],
                                              proxy_settings['port'])

            p = Password(pm, hostname,
                              "Squid proxy-caching web server",
                              proxy_settings["user"],
                              proxy_settings["passwd"])
            
            pm.insert_password(p)
    
        
