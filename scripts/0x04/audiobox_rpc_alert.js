function _play(code) {
  new NativeFunction(Module.findExportByName('AudioToolbox', 'AudioServicesPlaySystemSound'), 'void', ['int'])(code)
}

// Defining a Block that will be passed as handler parameter to +[UIAlertAction actionWithTitle:style:handler:]
var handler_for_alert = new ObjC.Block({
  retType: 'void',
  argTypes: ['object'],
  implementation: function () {
  }
});

// Import ObjC classes
var UIAlertController = ObjC.classes.UIAlertController;
var UIAlertAction = ObjC.classes.UIAlertAction;
var UIApplication = ObjC.classes.UIApplication;

function alert(text) {
    // Using Grand Central Dispatch to pass messages (invoke methods) in application's main thread
    ObjC.schedule(ObjC.mainQueue, function () {
      // Using integer numerals for preferredStyle which is of type enum UIAlertControllerStyle
      var alert = UIAlertController.alertControllerWithTitle_message_preferredStyle_('Frida AudioToolbox', text, 1);
      // Again using integer numeral for style parameter that is enum
      var defaultAction = UIAlertAction.actionWithTitle_style_handler_('OK', 0, handler_for_alert);
      alert.addAction_(defaultAction);
      // Instead of using `ObjC.choose()` and looking for UIViewController instances
      // on the heap, we have direct access through UIApplication:
      UIApplication.sharedApplication().keyWindow().rootViewController().presentViewController_animated_completion_(alert, true, NULL);

      // https://developer.apple.com/documentation/uikit/uiviewcontroller/1621505-dismissviewcontrolleranimated
      alert.dismissViewControllerAnimated_completion_(true, NULL);

    })
}

rpc.exports = {
    sms: function () {
        console.log('playing sms');
        alert('sms -> 1007');
        return _play(1007);
    },
    email: function () {
        console.log('playing email');
        alert('email -> 1000');
        return _play(1000);
    },
    lock: function () {
        console.log('playing lock');
        alert('lock -> 1100');
        return _play(1100);
    },
    photo: function () {
        console.log('playing photo');
        alert('photo -> 1108');
        return _play(1108);
    }
};
