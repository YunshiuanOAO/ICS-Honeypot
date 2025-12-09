import socket
import threading
import struct
import time
from db.database import LogDB

class ModbusPLC:
    def __init__(self, port=502, db: LogDB = None, model="Simulated Modbus Device", devices=None):
        self.host = '0.0.0.0'
        self.port = port
        self.db = db
        self.default_model = model
        # If devices are provided (Gateway mode), map unit_id to device config
        # Otherwise, treat as a single device (Unit ID 1 by default or any)
        self.devices = {}
        if devices:
            for d in devices:
                self.devices[d.get('unit_id')] = d
        else:
            # Legacy/Single mode: Map Unit ID 1 to default model
            self.devices[1] = {"unit_id": 1, "model": model}
        
        # Initialize storage for stateful emulation
        self.storage = {}
        
        print(f"DEBUG: ModbusPLC initialized with devices: {list(self.devices.keys())}")
        
        self.running = False
        self.sock = None
        self.thread = None

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._run_server)
        self.thread.daemon = True
        self.thread.start()
        print(f"Modbus PLC started on port {self.port}")

    def stop(self):
        self.running = False
        if self.sock:
            self.sock.close()
        print("Modbus PLC stopped")

    def _run_server(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((self.host, self.port))
            self.sock.listen(5)
            
            while self.running:
                try:
                    client_sock, addr = self.sock.accept()
                    client_handler = threading.Thread(
                        target=self._handle_client,
                        args=(client_sock, addr)
                    )
                    client_handler.start()
                except OSError:
                    break
        except Exception as e:
            print(f"Modbus Server Error: {e}")

    def _handle_client(self, client_sock, addr):
        attacker_ip = addr[0]
        print(f"Modbus connection from {attacker_ip}")
        
        try:
            while True:
                # Modbus TCP Header is 7 bytes
                # Transaction ID (2), Protocol ID (2), Length (2), Unit ID (1)
                header = client_sock.recv(7)
                if not header:
                    break
                
                trans_id, proto_id, length, unit_id = struct.unpack('>HHHB', header)
                print(f"DEBUG: Request for Unit ID: {unit_id}")
                
                # Read the PDU (Function Code + Data)
                # Length in header includes Unit ID (1 byte) + PDU
                pdu_length = length - 1
                pdu = client_sock.recv(pdu_length)
                
                full_request = header + pdu
                
                # Parse Function Code
                function_code = pdu[0]
                
                # Function Name Mapping
                FUNC_NAMES = {
                    1: "Read Coils",
                    2: "Read Discrete Inputs",
                    3: "Read Holding Registers",
                    4: "Read Input Registers",
                    5: "Write Single Coil",
                    6: "Write Single Register",
                    15: "Write Multiple Coils",
                    16: "Write Multiple Registers",
                    17: "Report Server ID",
                    43: "Encapsulated Interface Transport"
                }

                print(f"DEBUG: Received Modbus Func Code: {function_code} (0x{function_code:02X})")

                # Extract metadata for ELK
                meta = {
                    "modbus.unit_id": unit_id,
                    "modbus.func_code": function_code,
                    "modbus.func_name": FUNC_NAMES.get(function_code, "Unknown"),
                    "modbus.trans_id": trans_id
                }
                
                # Try to extract address and quantity for common function codes
                # Funcs 1, 2, 3, 4, 5, 6, 15, 16 usually start with Address(2)
                # Read Funcs also have Quantity(2)
                if len(pdu) >= 5: # Func(1) + Addr(2) + Quant/Val(2)
                    try:
                        addr, val_or_quant = struct.unpack('>HH', pdu[1:5])
                        meta["modbus.start_addr"] = addr
                        
                        if function_code in [1, 2, 3, 4]:
                            meta["modbus.quantity"] = val_or_quant
                        elif function_code in [5, 6]:
                            meta["modbus.write_value"] = val_or_quant # For Write Single
                        elif function_code in [15, 16]:
                            meta["modbus.quantity"] = val_or_quant
                            # For 15/16, ByteCount is at 5, Data starts at 6
                            # We can capture the raw data payload from the remaining PDU
                            if len(pdu) > 6:
                                meta["modbus.data_payload"] = pdu[6:].hex()
                    except:
                        pass
                
                # Generate a basic response FIRST to capture Exception Code
                if unit_id in self.devices:
                    response_pdu = self._handle_modbus_function(function_code, pdu[1:], unit_id)
                else:
                    # Gateway Path Unavailable (0x0A)
                    print(f"DEBUG: Unknown Unit ID {unit_id}")
                    response_pdu = struct.pack('BB', function_code + 0x80, 0x0A)
                
                # Check for Exception Code in Response
                if response_pdu and len(response_pdu) >= 2 and (response_pdu[0] & 0x80):
                    meta["modbus.exception_code"] = response_pdu[1]
                
                # Log the interaction
                if self.db:
                    self.db.log_interaction(
                        attacker_ip=attacker_ip,
                        protocol="modbus",
                        request_data=full_request,
                        response_data=b"" if not response_pdu else response_pdu, # Store raw response
                        metadata=meta
                    )

                # Response is already generated above for logging purposes
                
                if response_pdu:
                    # Check if exception (Print debug)
                    if len(response_pdu) >= 2 and (response_pdu[0] & 0x80):
                        print(f"DEBUG: Sending Exception Response: Code 0x{response_pdu[1]:02X}")
                    else:
                        print(f"DEBUG: Sending Success Response for Func 0x{function_code:02X}")
                
                response_length = 1 + len(response_pdu) # Unit ID + PDU
                response_header = struct.pack('>HHHB', trans_id, proto_id, response_length, unit_id)
                
                full_response = response_header + response_pdu
                client_sock.send(full_response)
                
                # Update log with response (optional, or log separately)
                # For now, we just logged the request. 
                
        except Exception as e:
            print(f"Error handling Modbus client {addr}: {e}")
        finally:
            client_sock.close()

    def _handle_modbus_function(self, func_code, data, unit_id):
        # Basic implementation of common function codes
        # 0x01 Read Coils
        # 0x03 Read Holding Registers
        
        # Ensure storage exists for this unit_id (lazy initialization if needed, though __init__ should handle it)
        if unit_id not in self.storage:
            self.storage[unit_id] = {'coils': {}, 'holding_registers': {}}

        if func_code == 1: # Read Coils
            # Request: Start Addr (2), Quantity (2)
            # Response: Byte Count (1), Coil Status (n)
            if len(data) >= 4:
                start_addr, quantity = struct.unpack('>HH', data[:4])
                byte_count = (quantity + 7) // 8
                
                # Construct coil status bytes
                coil_bytes = bytearray(byte_count)
                for i in range(quantity):
                    addr = start_addr + i
                    # Get value from storage, default to False (0)
                    val = self.storage[unit_id]['coils'].get(addr, False)
                    if val:
                        byte_index = i // 8
                        bit_index = i % 8
                        coil_bytes[byte_index] |= (1 << bit_index)
                
                return struct.pack('BB', func_code, byte_count) + coil_bytes
            
        elif func_code == 3: # Read Holding Registers
            # Request: Start Addr (2), Quantity (2)
            # Response: Byte Count (1), Register Values (n*2)
            if len(data) >= 4:
                start_addr, quantity = struct.unpack('>HH', data[:4])
                byte_count = quantity * 2
                
                resp_data = b""
                for i in range(quantity):
                    addr = start_addr + i
                    # Get value from storage, default to 0. 
                    # If not set, we can return a default or unit_id * 1111 as before for "uninitialized" ones?
                    # Let's default to 0 for clean state, or keep the old behavior for unwritten ones.
                    # User wants "modification", so default 0 is fine, or we can pre-populate.
                    # Let's use 0 as default.
                    val = self.storage[unit_id]['holding_registers'].get(addr, 0)
                    resp_data += struct.pack('>H', val)
                
                return struct.pack('BB', func_code, byte_count) + resp_data

        elif func_code == 2: # Read Discrete Inputs
            # Similar to Read Coils
            if len(data) >= 4:
                quantity = struct.unpack('>H', data[2:4])[0]
                byte_count = (quantity + 7) // 8
                return struct.pack('BB', func_code, byte_count) + b'\x00' * byte_count

        elif func_code == 4: # Read Input Registers
            # Similar to Read Holding Registers
            if len(data) >= 4:
                quantity = struct.unpack('>H', data[2:4])[0]
                byte_count = quantity * 2
                val = 0 # Just return 0 for inputs
                return struct.pack('BB', func_code, byte_count) + (struct.pack('>H', val) * quantity)

        elif func_code == 5: # Write Single Coil
            # Request: Address(2), Value(2)
            # Response: Echo Request
            if len(data) >= 4:
                addr, val_raw = struct.unpack('>HH', data[:4])
                # Value 0xFF00 = ON, 0x0000 = OFF
                val = (val_raw == 0xFF00)
                
                # Update storage
                self.storage[unit_id]['coils'][addr] = val
                print(f"DEBUG: Unit {unit_id} Coil {addr} set to {val}")
                
                return struct.pack('B', func_code) + data[:4]

        elif func_code == 6: # Write Single Register
            # Request: Address(2), Value(2)
            # Response: Echo Request
            if len(data) >= 4:
                addr, val = struct.unpack('>HH', data[:4])
                
                # Update storage
                self.storage[unit_id]['holding_registers'][addr] = val
                print(f"DEBUG: Unit {unit_id} Register {addr} set to {val}")
                
                return struct.pack('B', func_code) + data[:4]

        elif func_code == 17: # Report Server ID (0x11)
            # Response: Byte Count (1), Server ID (n), Run Indicator (1)
            # We'll return the model name and Run Indicator 0xFF (Running)
            
            # Get model name for this Unit ID
            device_conf = self.devices.get(unit_id)
            if device_conf:
                current_model = device_conf.get("model", "Unknown")
            else:
                current_model = "Unknown Device"
                
            server_id = current_model.encode('utf-8')
            byte_count = len(server_id) + 1
            return struct.pack('BB', func_code, byte_count) + server_id + b'\xFF'

        elif func_code == 0x2B: # Encapsulated Interface Transport
            # Check MEI Type (14 for Read Device Identification)
            if len(data) >= 3 and data[0] == 0x0E:
                # Read Device ID code (1: Basic, 2: Regular, 3: Extended, 4: Specific)
                read_code = data[1]
                object_id = data[2] # Object ID to start at
                
                # Construct Basic Device Identification (Stream access)
                # MEI Type (1), Read Device ID (1), Conformity Level (1), More Follows (1), Next Obj Id (1), Number of Objects (1)
                
                # Get model name for this Unit ID
                device_conf = self.devices.get(unit_id)
                if device_conf:
                    current_model = device_conf.get("model", "Unknown")
                else:
                    # Gateway Path Unavailable (0x0A) or just return Unknown
                    # For simplicity, let's return Unknown or handle as error
                    # return struct.pack('BB', func_code + 0x80, 0x0A)
                    current_model = "Unknown Device"

                vendor_name = b"Schneider Electric"
                product_code = current_model.encode('utf-8')
                major_minor_revision = b"V1.0.0"
                
                objects = [
                    (0x00, vendor_name),
                    (0x01, product_code),
                    (0x02, major_minor_revision)
                ]
                
                obj_data = b""
                
                for oid, content in objects:
                    # Simple implementation: return all basic objects
                    obj_data += struct.pack('BB', oid, len(content)) + content
                
                # More Follows (0xFF if more, 0x00 if done). Here we assume all fit in one PDU
                more_follows = 0x00
                next_obj_id = 0x00
                conformity_level = 0x01 # Basic-stream only
                
                resp_data = struct.pack('BBBBBB', 0x0E, read_code, conformity_level, more_follows, next_obj_id, len(objects)) + obj_data
                return struct.pack('B', func_code) + resp_data

        # Default: Illegal Function (0x01)
        # Error response: Function Code + 0x80, Exception Code
        return struct.pack('BB', func_code + 0x80, 0x01)
