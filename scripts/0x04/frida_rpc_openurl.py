import codecs
import frida
from time import sleep

session = frida.get_usb_device().attach('Telegram')

with codecs.open('./openurl_rpc.js', 'r', 'utf-8') as f:
    source = f.read()

script = session.create_script(source)
script.load()

open_twitter_about = script.exports.openurl("https://twitter.com/about")
print(f'Result: {open_twitter_about}') # Will show True/False

session.detach()
