import codecs
import frida
from time import sleep

session = frida.get_usb_device().attach('Telegram')

with codecs.open('./audiobox_rpc_alert.js', 'r', 'utf-8') as f:
    source = f.read()

script = session.create_script(source)
script.load()

rpc = script.exports

rpc.sms()
sleep(1)
rpc.email()
sleep(1)
rpc.lock()
sleep(1)
rpc.photo()

session.detach()
