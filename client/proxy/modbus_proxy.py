"""
Modbus TCP Proxy
Captures and parses Modbus TCP traffic with full protocol awareness.
"""

import struct
import socket
from typing import Tuple, Optional

from .base_proxy import BaseProxy, ProxyConfig
from .unified_logger import UnifiedLogger, ProtocolInfo


# Modbus Function Code Names
MODBUS_FUNCTION_NAMES = {
    0x01: "Read Coils",
    0x02: "Read Discrete Inputs",
    0x03: "Read Holding Registers",
    0x04: "Read Input Registers",
    0x05: "Write Single Coil",
    0x06: "Write Single Register",
    0x07: "Read Exception Status",
    0x08: "Diagnostics",
    0x0B: "Get Comm Event Counter",
    0x0C: "Get Comm Event Log",
    0x0F: "Write Multiple Coils",
    0x10: "Write Multiple Registers",
    0x11: "Report Server ID",
    0x14: "Read File Record",
    0x15: "Write File Record",
    0x16: "Mask Write Register",
    0x17: "Read/Write Multiple Registers",
    0x18: "Read FIFO Queue",
    0x2B: "Encapsulated Interface Transport",
}

# Modbus Exception Codes
MODBUS_EXCEPTION_CODES = {
    0x01: "Illegal Function",
    0x02: "Illegal Data Address",
    0x03: "Illegal Data Value",
    0x04: "Server Device Failure",
    0x05: "Acknowledge",
    0x06: "Server Device Busy",
    0x08: "Memory Parity Error",
    0x0A: "Gateway Path Unavailable",
    0x0B: "Gateway Target Device Failed to Respond",
}


class ModbusProxy(BaseProxy):
    """
    Modbus TCP protocol-aware proxy.
    
    Features:
    - Full Modbus TCP/IP frame parsing
    - Function code identification
    - Register/coil address extraction
    - Exception code detection
    - MEI (Read Device Identification) support
    
    Frame Structure:
    +------------------+------------------+------------------+------------------+
    | Transaction ID   | Protocol ID      | Length           | Unit ID          |
    | (2 bytes)        | (2 bytes)        | (2 bytes)        | (1 byte)         |
    +------------------+------------------+------------------+------------------+
    | Function Code    | Data             |
    | (1 byte)         | (variable)       |
    +------------------+------------------+
    
    Example:
        config = ProxyConfig(
            listen_port=502,
            backend_host="127.0.0.1",
            backend_port=5020,
            protocol="modbus",
            node_id="node-01",
            deployment_id="plc-01",
        )
        logger = UnifiedLogger("/var/log/honeypot", "node-01", "plc-01")
        proxy = ModbusProxy(config, logger)
        proxy.start()
    """
    
    # Modbus TCP header is 7 bytes (MBAP Header)
    MBAP_HEADER_SIZE = 7
    
    def __init__(self, config: ProxyConfig, logger: UnifiedLogger, **kwargs):
        super().__init__(config, logger, **kwargs)
        self._request_contexts: dict = {}  # Store request context for response parsing
    
    def parse_request(self, data: bytes, session_id: str = "") -> dict:
        """Parse Modbus TCP request frame"""
        result = {
            "valid": False,
            "raw_length": len(data),
        }
        
        if len(data) < self.MBAP_HEADER_SIZE + 1:  # Header + at least function code
            result["error"] = "Frame too short"
            return result
        
        try:
            # Parse MBAP Header
            trans_id, proto_id, length, unit_id = struct.unpack(">HHHB", data[:7])
            
            result["modbus.transaction_id"] = trans_id
            result["modbus.protocol_id"] = proto_id
            result["modbus.length"] = length
            result["modbus.unit_id"] = unit_id
            
            # Parse PDU
            pdu = data[7:]
            if not pdu:
                result["error"] = "Empty PDU"
                return result
            
            func_code = pdu[0]
            result["modbus.function_code"] = func_code
            result["modbus.function_name"] = MODBUS_FUNCTION_NAMES.get(func_code, f"Unknown (0x{func_code:02X})")
            
            # Parse function-specific data
            func_data = pdu[1:]
            self._parse_function_request(func_code, func_data, result)
            
            result["valid"] = True
            
            # Store context for response parsing
            self._request_contexts[session_id] = {
                "func_code": func_code,
                "unit_id": unit_id,
                "trans_id": trans_id,
            }
            
        except struct.error as e:
            result["error"] = f"Parse error: {e}"
        
        return result
    
    def parse_response(self, data: bytes, request_context: dict = None) -> dict:
        """Parse Modbus TCP response frame"""
        result = {
            "valid": False,
            "raw_length": len(data),
        }
        
        if not data:
            result["empty"] = True
            return result
        
        if len(data) < self.MBAP_HEADER_SIZE + 1:
            result["error"] = "Frame too short"
            return result
        
        try:
            # Parse MBAP Header
            trans_id, proto_id, length, unit_id = struct.unpack(">HHHB", data[:7])
            
            result["modbus.transaction_id"] = trans_id
            result["modbus.unit_id"] = unit_id
            
            # Parse PDU
            pdu = data[7:]
            func_code = pdu[0]
            
            # Check for exception response
            if func_code & 0x80:
                original_func = func_code & 0x7F
                exception_code = pdu[1] if len(pdu) > 1 else 0
                
                result["modbus.is_exception"] = True
                result["modbus.original_function_code"] = original_func
                result["modbus.exception_code"] = exception_code
                result["modbus.exception_name"] = MODBUS_EXCEPTION_CODES.get(
                    exception_code, f"Unknown (0x{exception_code:02X})"
                )
            else:
                result["modbus.function_code"] = func_code
                result["modbus.function_name"] = MODBUS_FUNCTION_NAMES.get(func_code, f"Unknown (0x{func_code:02X})")
                result["modbus.is_exception"] = False
                
                # Parse function-specific response data
                func_data = pdu[1:]
                self._parse_function_response(func_code, func_data, result, request_context)
            
            result["valid"] = True
            
        except struct.error as e:
            result["error"] = f"Parse error: {e}"
        
        return result
    
    def get_protocol_info(self) -> ProtocolInfo:
        """Return Modbus TCP protocol info"""
        return ProtocolInfo(
            name="modbus",
            layer="application",
            version="tcp",
        )
    
    def _parse_function_request(self, func_code: int, data: bytes, result: dict):
        """Parse function-specific request data"""
        
        if func_code in (0x01, 0x02, 0x03, 0x04):  # Read Coils/DI/HR/IR
            if len(data) >= 4:
                start_addr, quantity = struct.unpack(">HH", data[:4])
                result["modbus.start_address"] = start_addr
                result["modbus.quantity"] = quantity
                
        elif func_code == 0x05:  # Write Single Coil
            if len(data) >= 4:
                addr, value = struct.unpack(">HH", data[:4])
                result["modbus.address"] = addr
                result["modbus.value"] = value == 0xFF00  # True/False
                
        elif func_code == 0x06:  # Write Single Register
            if len(data) >= 4:
                addr, value = struct.unpack(">HH", data[:4])
                result["modbus.address"] = addr
                result["modbus.value"] = value
                
        elif func_code == 0x0F:  # Write Multiple Coils
            if len(data) >= 5:
                start_addr, quantity, byte_count = struct.unpack(">HHB", data[:5])
                result["modbus.start_address"] = start_addr
                result["modbus.quantity"] = quantity
                result["modbus.byte_count"] = byte_count
                if len(data) > 5:
                    result["modbus.write_data"] = data[5:].hex()
                    
        elif func_code == 0x10:  # Write Multiple Registers
            if len(data) >= 5:
                start_addr, quantity, byte_count = struct.unpack(">HHB", data[:5])
                result["modbus.start_address"] = start_addr
                result["modbus.quantity"] = quantity
                result["modbus.byte_count"] = byte_count
                if len(data) > 5:
                    # Parse register values
                    values = []
                    for i in range(0, min(quantity * 2, len(data) - 5), 2):
                        if i + 2 <= len(data) - 5:
                            val = struct.unpack(">H", data[5+i:7+i])[0]
                            values.append(val)
                    result["modbus.values"] = values
                    
        elif func_code == 0x2B:  # Encapsulated Interface Transport (MEI)
            if len(data) >= 3 and data[0] == 0x0E:  # Read Device ID
                mei_type = data[0]
                read_code = data[1]
                object_id = data[2]
                result["modbus.mei_type"] = mei_type
                result["modbus.read_device_id_code"] = read_code
                result["modbus.object_id"] = object_id
                result["modbus.function_name"] = "Read Device Identification"
    
    def _parse_function_response(self, func_code: int, data: bytes, result: dict, request_context: dict = None):
        """Parse function-specific response data"""
        
        if func_code in (0x01, 0x02):  # Read Coils/DI Response
            if len(data) >= 1:
                byte_count = data[0]
                result["modbus.byte_count"] = byte_count
                if len(data) > 1:
                    coil_data = data[1:1+byte_count]
                    result["modbus.coil_data"] = coil_data.hex()
                    
        elif func_code in (0x03, 0x04):  # Read HR/IR Response
            if len(data) >= 1:
                byte_count = data[0]
                result["modbus.byte_count"] = byte_count
                if len(data) > 1:
                    # Parse register values
                    values = []
                    for i in range(1, min(byte_count + 1, len(data)), 2):
                        if i + 2 <= len(data):
                            val = struct.unpack(">H", data[i:i+2])[0]
                            values.append(val)
                    result["modbus.values"] = values
                    
        elif func_code in (0x05, 0x06):  # Write Single Coil/Register Response (Echo)
            if len(data) >= 4:
                addr, value = struct.unpack(">HH", data[:4])
                result["modbus.address"] = addr
                result["modbus.value"] = value
                
        elif func_code in (0x0F, 0x10):  # Write Multiple Response
            if len(data) >= 4:
                start_addr, quantity = struct.unpack(">HH", data[:4])
                result["modbus.start_address"] = start_addr
                result["modbus.quantity"] = quantity
                
        elif func_code == 0x11:  # Report Server ID
            if len(data) >= 1:
                byte_count = data[0]
                result["modbus.byte_count"] = byte_count
                if len(data) > 1:
                    # Server ID is typically ASCII string + Run Indicator
                    server_id_data = data[1:byte_count]
                    try:
                        result["modbus.server_id"] = server_id_data.decode("utf-8", errors="replace").rstrip("\xff\x00")
                    except Exception:
                        result["modbus.server_id_hex"] = server_id_data.hex()
                    if len(data) > byte_count:
                        result["modbus.run_indicator"] = data[byte_count] == 0xFF
                        
        elif func_code == 0x2B:  # MEI Response
            if len(data) >= 6 and data[0] == 0x0E:
                result["modbus.mei_type"] = data[0]
                result["modbus.read_device_id_code"] = data[1]
                result["modbus.conformity_level"] = data[2]
                result["modbus.more_follows"] = data[3]
                result["modbus.next_object_id"] = data[4]
                num_objects = data[5]
                result["modbus.num_objects"] = num_objects
                
                # Parse objects
                objects = {}
                offset = 6
                for _ in range(num_objects):
                    if offset + 2 > len(data):
                        break
                    obj_id = data[offset]
                    obj_len = data[offset + 1]
                    offset += 2
                    if offset + obj_len <= len(data):
                        obj_value = data[offset:offset + obj_len]
                        try:
                            objects[obj_id] = obj_value.decode("utf-8")
                        except Exception:
                            objects[obj_id] = obj_value.hex()
                        offset += obj_len
                
                result["modbus.device_objects"] = objects
                # Common object IDs
                if 0 in objects:
                    result["modbus.vendor_name"] = objects[0]
                if 1 in objects:
                    result["modbus.product_code"] = objects[1]
                if 2 in objects:
                    result["modbus.revision"] = objects[2]
    
    def _read_response(self, backend_sock: socket.socket, request_context: dict) -> bytes:
        """
        Read complete Modbus TCP response.
        Modbus TCP uses length field in header to know how much to read.
        """
        # Read MBAP header first
        header = b""
        while len(header) < self.MBAP_HEADER_SIZE:
            chunk = backend_sock.recv(self.MBAP_HEADER_SIZE - len(header))
            if not chunk:
                return header
            header += chunk
        
        if len(header) < self.MBAP_HEADER_SIZE:
            return header
        
        # Get length from header
        _, _, length, _ = struct.unpack(">HHHB", header)
        
        # Length includes Unit ID (1 byte), so remaining PDU is (length - 1) bytes
        remaining = length - 1
        
        # Read rest of frame
        pdu = b""
        while len(pdu) < remaining:
            chunk = backend_sock.recv(min(remaining - len(pdu), self.config.buffer_size))
            if not chunk:
                break
            pdu += chunk
        
        return header + pdu
    
    def _cleanup_session(self, session_id: str):
        """Clean up session-specific request context to prevent memory leak"""
        self._request_contexts.pop(session_id, None)
