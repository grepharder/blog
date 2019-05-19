console.log('Tags: sms, email, lock, photo')

function play(tag) {
  switch(tag) {
    case 'sms':
    _play(1007)
    break;
    case 'email':
    _play(1000)
    break;
    case 'lock':
    _play(1100)
    break;
    case 'photo':
    _play(1108)
    break;
  }

}

function _play(code) {
  new NativeFunction(Module.findExportByName('AudioToolbox', 'AudioServicesPlaySystemSound'), 'void', ['int'])(code)
}
