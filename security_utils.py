import ctypes
import numpy as np

def secure_wipe(data):
    """Securely overwrite sensitive data in memory"""
    if isinstance(data, str):
        data = data.encode('utf-8')
    buffer = np.frombuffer(data, dtype=np.uint8)
    
    # Optional: Print before wiping (show part of the buffer)
    print(f"Before wipe: {buffer[:16]}...")  # Only showing part for readability
    
    ctypes.memset(ctypes.c_void_p(buffer.ctypes.data), 0, buffer.size)
    
    # Print after wiping (should show zeros)
    print(f"After wipe:  {buffer[:16]}...")
    
    del buffer
