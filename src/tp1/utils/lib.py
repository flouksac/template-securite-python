# src/tp1/utils/lib.py

import platform
from scapy.all import get_if_list

try:
    from scapy.arch.windows import get_windows_if_list
except Exception:
    get_windows_if_list = None


def hello_world() -> str:
    """
    Hello world function
    """
    return "hello world"


def choose_interface() -> str:
    """
    Return network interface and input user choice
    """
    system = platform.system().lower()

    if system == "windows" and get_windows_if_list:
        try:
            win_ifaces = get_windows_if_list()
            display_list = []
            real_names = []

            for it in win_ifaces:
                desc = it.get("description") or it.get("iface") or it.get("name")
                name = it.get("name")
                display_list.append(f"{desc} ({name})")
                real_names.append(name)

            ifaces = real_names

            for i, disp in enumerate(display_list, 1):
                print(f"{i}: {disp}")

        except Exception:
            ifaces = get_if_list()
            for i, name in enumerate(ifaces, 1):
                print(f"{i}: {name}")
    else:
        ifaces = get_if_list()
        for i, name in enumerate(ifaces, 1):
            print(f"{i}: {name}")

    choice = input("Choisissez l'interface (nom ou numéro) à écouter avec Scapy (enter = default): ").strip()

    if choice.isdigit():
        idx = int(choice) - 1
        if 0 <= idx < len(ifaces):
            return ifaces[idx]

    for name in ifaces:
        if name == choice or name.lower() == choice.lower() or choice.lower() in name.lower():
            return name

    return ifaces[0] if ifaces else None