function openURL(url) {
   var UIApplication = ObjC.classes.UIApplication.sharedApplication();
   var toOpen = ObjC.classes.NSURL.URLWithString_(url);
   return UIApplication.openURL_(toOpen);
}

rpc.exports = {
    openurl: function (url) {
        console.log('[Frida iOS RPC Stub] called openurl: ' + url);
        return openURL(url);
    }
};
