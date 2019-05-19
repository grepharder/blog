function _play(code) {
  new NativeFunction(Module.findExportByName('AudioToolbox', 'AudioServicesPlaySystemSound'), 'void', ['int'])(code)
}

rpc.exports = {
    sms: function () {
        return _play(1007);
    },
    email: function () {
        return _play(1000);
    },
    lock: function () {
        return _play(1100);
    },
    photo: function () {
        return _play(1108);
    },
};
