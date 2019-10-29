# -*- coding: utf-8 -*-
# import frida

js_code = """
    console.log("加载脚本成功！");
Java.perform(function x() {
    //定位StringBuilder,StringBuffer类
    const app = Java.use("com.m4399.framework.helpers.AppNativeHelper");

    app.getServerApi.overload("java.lang.String").implementation = function(a1){
        var result = this.getServerApi("1");
        console.log(result);
        return result;
    }
});
"""


import sys
import frida

# 连接安卓机上的frida-server
device = frida.get_usb_device()

# 选择应用包名
appPackageName = "com.xiwang.demo"

# 附加
session = device.attach(appPackageName)

# 加载脚本
script = session.create_script(js_code)
script.load()

sys.stdin.read()


