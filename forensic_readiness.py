# linux_audit_trail_config.py

"""
Description:
    Checks if your Linux system is ready for Cyber Forensic evidence collection and further analysis.

    We only discuss 3 simple controls for this talk. However, in a real life scenario, one may have 
    100s of such controls and a master script/function to call them all.

Author:
    Nishant Krishna

Created:
    14 April, 2024
"""


import platform
import subprocess
from pathlib import Path

class CyberForensicsChecker:
    NO_RULES = 'No rules'
    PASS = 'PASS'
    PARTIAL_PASS = 'PARTIAL PASS'
    FAIL = 'FAIL'
    ENABLED = 'enabled'


    def get_auditctl_config(self, config):
        '''
        Control to check auditctl status for a given file.
        '''
        if platform.system() == 'Linux':
            print('\n--- Control - Audit log check ---')
            output = subprocess.check_output('auditctl -l', shell=True)
            output_list = output.decode('utf-8').split('\n')

            if (len(output_list) == 2 and output_list[0] == self.NO_RULES):
                print ('Check audit rules:\t', self.FAIL)
            else:
                # Find out if the audit config is present for supplied config
                # TODO Add partical pass scenarios
                for config_item in output_list:
                    if config in config_item:
                        print('Audit config for ', config, ' found:')
                        print(config_item)

                print ('Check audit rules:\t', self.PASS)
        else:
            print('This program can only be run on Linux')


    def check_syslog_status(self):
        '''
        Control to check the Syslog NG status
        '''
        print('\n--- Control - Syslog NG Check ---')
        output = subprocess.check_output('systemctl --no-pager status syslog-ng | grep dead', shell=True)

        # Decode to utf-8 as we get a byte
        if (output.decode('utf-8').count(self.ENABLED) == 2):
            print ('Check syslog_ng status:\t', self.PASS)
        else:
            print ('Check syslog_ng status:\t', self.FAIL)


    def check_crontab_status(self):
        '''
        Control to check if crontab has been modified from the last time.

        In order to test this function, you can run the following first:
        $ stat /etc/crontab | grep Change > crontab_stat.txt

        followed by a change in the crontab and then running this function
        '''
        print('\n--- Control - Check Crontab Status ---')

        output = (subprocess.check_output('stat /etc/crontab | grep Change', shell=True)).decode('utf-8')

        file_path = Path(__file__).with_name('crontab_stat.txt')
        with file_path.open('r') as crontab_file:
            change_date = crontab_file.read()

            if (output == change_date):
                print ('Check crontab status:\t', self.PASS)
            else:
                print ('Check crontab status:\t', self.FAIL)
    

if __name__ == "__main__":
    cyber_forensic_checker = CyberForensicsChecker()
    cyber_forensic_checker.get_auditctl_config('passwd')
    cyber_forensic_checker.check_syslog_status()
    cyber_forensic_checker.check_crontab_status()

