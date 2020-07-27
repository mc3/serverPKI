from subprocess import Popen, PIPE

def connect_to_ide():
    if hostname('somehost'):
        import pydevd_pycharm
        pydevd_pycharm.settrace('my_desktop_pc', port=9876, stdoutToServer=True, stderrToServer=True)


def hostname(name:str) -> bool:
    """
    Check for hostname of development server
    No PyCharm debugger if running test suite on localhost
    :param name: hostname of remote development server
    :return: True if hostname match name
    """
    p = process=Popen('hostname', stdout=PIPE, text=True)
    stdout, stderr = p.communicate()
    return stdout.strip() == name
