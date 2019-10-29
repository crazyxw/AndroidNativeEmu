import logging
import posixpath
import sys

from unicorn import UcError, UC_HOOK_MEM_UNMAPPED
from unicorn.arm_const import *

from androidemu.emulator import Emulator
from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_method_def import java_method_def

from samples import debug_utils


# metaclass 固定写法  jvm_name 指定类名, 把.换成/
class GetServerApi(metaclass=JavaClassDef, jvm_name='com/m4399/framework/helpers/AppNativeHelper'):
    def __init__(self):
        pass

    # name指定要执行的native方法 signature方法签名 native是否是native方法
    @java_method_def(name='getServerApi', signature='(Ljava/lang/String;)Ljava/lang/String;', native=True)
    def getServerApi(self):
        pass


# Configure logging
logging.basicConfig(
    stream=sys.stdout,
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)7s %(name)34s | %(message)s"
)

logger = logging.getLogger(__name__)

# Initialize emulator
emulator = Emulator(
    vfp_inst_set=True,
    vfs_root=posixpath.join(posixpath.dirname(__file__), "vfs")
)

# Register Java class.
emulator.java_classloader.add_class(GetServerApi)

# Load all libraries.
emulator.load_library("example_binaries/libdl.so")
emulator.load_library("example_binaries/libc.so")
emulator.load_library("example_binaries/libstdc++.so")
emulator.load_library("example_binaries/libm.so")
# 加载要调式的so
lib_module = emulator.load_library("example_binaries/libm4399.so")

# Show loaded modules.
logger.info("Loaded modules:")

for module in emulator.modules:
    logger.info("=> 0x%08x - %s" % (module.base, module.filename))

# Debug
# emulator.mu.hook_add(UC_HOOK_CODE, debug_utils.hook_code)
emulator.mu.hook_add(UC_HOOK_MEM_UNMAPPED, debug_utils.hook_unmapped)

try:
    # Run JNI_OnLoad.
    #   JNI_OnLoad will call 'RegisterNatives'.
    emulator.call_symbol(lib_module, 'JNI_OnLoad', emulator.java_vm.address_ptr, 0x00)
    x = GetServerApi()
    result = x.getServerApi(emulator, "1")
    print(result)


except UcError as e:
    print("Exit at %x" % emulator.mu.reg_read(UC_ARM_REG_PC))
    raise
