import sys
from os_ken.base.app_manager import AppManager
from os_ken import cfg

def main():
    # Set the OpenFlow listening port
    conf = cfg.CONF
    conf(['--ofp-tcp-listen-port', '6633'])

    app_lists = ['simple_switch']
    AppManager.run_apps(app_lists)

if __name__ == '__main__':
    main()