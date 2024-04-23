# created with "nrfutil toolchain-manager env --as-script sh" (except the last line)

ZEPHYR_TOOLS=/home/hardy/ncs/toolchains/2be090971e
export PATH=$ZEPHYR_TOOLS/usr/bin:$ZEPHYR_TOOLS/usr/bin:$ZEPHYR_TOOLS/usr/local/bin:$ZEPHYR_TOOLS/opt/bin:$ZEPHYR_TOOLS/opt/nanopb/generator-bin:$ZEPHYR_TOOLS/opt/zephyr-sdk/aarch64-zephyr-elf/bin:$ZEPHYR_TOOLS/opt/zephyr-sdk/x86_64-zephyr-elf/bin:$ZEPHYR_TOOLS/opt/zephyr-sdk/arm-zephyr-eabi/bin:$ZEPHYR_TOOLS/opt/zephyr-sdk/riscv64-zephyr-elf/bin:$PATH
export LD_LIBRARY_PATH=$ZEPHYR_TOOLS/usr/lib:$ZEPHYR_TOOLS/usr/lib/x86_64-linux-gnu:$ZEPHYR_TOOLS/usr/local/lib:$LD_LIBRARY_PATH
export GIT_EXEC_PATH=$ZEPHYR_TOOLS/usr/local/libexec/git-core
export GIT_TEMPLATE_DIR=$ZEPHYR_TOOLS/usr/local/share/git-core/templates
export PYTHONHOME=$ZEPHYR_TOOLS/usr/local
export PYTHONPATH=$ZEPHYR_TOOLS/usr/local/lib/python3.9:$ZEPHYR_TOOLS/usr/local/lib/python3.9/site-packages
export ZEPHYR_TOOLCHAIN_VARIANT=zephyr
export ZEPHYR_SDK_INSTALL_DIR=$ZEPHYR_TOOLS/opt/zephyr-sdk

#. /home/hardy/ncs/v2.6.0/zephyr/zephyr-env.sh
. /home/hardy/zephyrproject/zephyr/zephyr-env.sh
