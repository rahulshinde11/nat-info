const stun = require('stun');
const dgram = require('dgram');
const os = require('os');

// STUN servers for initial connectivity and mapping tests
const STUN_SERVERS = [
  { host: 'stun.l.google.com', port: 19302 },
  { host: 'stun1.l.google.com', port: 19302 },
  { host: 'stun.stunprotocol.org', port: 3478 }
];

// Servers that are known to support RFC 3489 (CHANGE-REQUEST) attributes
// Required for distinguishing Full Cone vs Restricted Cone
const RFC3489_SERVERS = [
  { host: 'stun.sipgate.net', port: 3478 },
  { host: 'stun.voipstunt.com', port: 3478 },
  { host: 'stun.schlund.de', port: 3478 }
];

// Get local IP address used for internet routing
function getLocalIP() {
  return new Promise((resolve) => {
    const socket = dgram.createSocket('udp4');
    socket.connect(80, '8.8.8.8', () => {
      const address = socket.address().address;
      socket.close();
      resolve(address);
    });
    socket.on('error', () => {
      socket.close();
      resolve('127.0.0.1');
    });
  });
}

// Parse STUN message to extract XOR-MAPPED-ADDRESS or MAPPED-ADDRESS
function parseStunResponse(buffer) {
  // STUN message format:
  // 0-1: Message type (2 bytes)
  // 2-3: Message length (2 bytes)
  // 4-7: Magic cookie (4 bytes)
  // 8-11: Transaction ID (12 bytes)
  // Then attributes...
  
  if (buffer.length < 20) {
    return null;
  }
  
  const messageType = buffer.readUInt16BE(0);
  const magicCookie = buffer.readUInt32BE(4);
  
  // Check if it's a binding response (0x0101)
  if (messageType !== 0x0101) {
    return null;
  }
  
  // Magic Cookie check (RFC 5389)
  const isRFC5389 = (magicCookie === 0x2112A442);
  
  let offset = 20; // Start after header
  
  while (offset < buffer.length - 4) {
    const attrType = buffer.readUInt16BE(offset);
    const attrLength = buffer.readUInt16BE(offset + 2);
    offset += 4;
    
    // XOR-MAPPED-ADDRESS = 0x0020
    if (attrType === 0x0020 && attrLength >= 8) {
      const family = buffer.readUInt8(offset + 1);
      if (family === 0x01) { // IPv4
        let port = buffer.readUInt16BE(offset + 2);
        let ip1 = buffer.readUInt8(offset + 4);
        let ip2 = buffer.readUInt8(offset + 5);
        let ip3 = buffer.readUInt8(offset + 6);
        let ip4 = buffer.readUInt8(offset + 7);

        if (isRFC5389) {
            port ^= 0x2112;
            ip1 ^= 0x21;
            ip2 ^= 0x12;
            ip3 ^= 0xA4;
            ip4 ^= 0x42;
        }
        
        const ip = `${ip1}.${ip2}.${ip3}.${ip4}`;
        return { ip, port };
      }
    }
    
    // MAPPED-ADDRESS = 0x0001 (fallback)
    if (attrType === 0x0001 && attrLength >= 8) {
      const family = buffer.readUInt8(offset + 1);
      if (family === 0x01) { // IPv4
        const port = buffer.readUInt16BE(offset + 2);
        const ip1 = buffer.readUInt8(offset + 4);
        const ip2 = buffer.readUInt8(offset + 5);
        const ip3 = buffer.readUInt8(offset + 6);
        const ip4 = buffer.readUInt8(offset + 7);
        const ip = `${ip1}.${ip2}.${ip3}.${ip4}`;
        return { ip, port };
      }
    }
    
    // Move to next attribute (pad to 4-byte boundary)
    offset += attrLength;
    offset = (offset + 3) & ~3;
  }
  
  return null;
}

// Make a single STUN request with transaction ID matching and optional attributes
async function makeStunRequest(socket, serverHost, serverPort, attributes = [], timeoutMs = 3000, expectDifferentSource = false) {
  // Always resolve server hostname to IP for consistent behavior
  const dns = require('dns').promises;
  let resolvedServerIP = serverHost;
  
  try {
    const addresses = await dns.resolve4(serverHost);
    if (addresses && addresses.length > 0) {
      resolvedServerIP = addresses[0];
    }
  } catch (e) {
    // If resolution fails, just use hostname
  }
  
  return new Promise((resolve, reject) => {
    const request = stun.createMessage(stun.constants.STUN_BINDING_REQUEST);
    
    // Add attributes if provided
    if (attributes && attributes.length > 0) {
        attributes.forEach(attr => {
            request.addAttribute(attr.type, attr.value);
        });
    }

    const requestBuffer = stun.encode(request);
    
    // Extract transaction ID (bytes 4-19 for RFC3489, 8-19 for RFC5389 but library handles structure)
    // We'll rely on the library's transaction ID generation or extract from buffer
    // The library likely puts random transaction ID.
    // Let's trust the buffer structure from 'stun.encode'.
    // RFC 5389: Header is 20 bytes. Transaction ID is at offset 8 (12 bytes).
    // RFC 3489: Transaction ID is at offset 4 (16 bytes).
    // We'll match the last 12 bytes which are common to both effectively for matching purposes if we use the buffer slice.
    
    // Note: 'stun' lib creates RFC5389 messages by default (Magic Cookie). 
    // Transaction ID is 12 bytes at offset 8.
    const transactionId = requestBuffer.slice(8, 20);
    
    const timeout = setTimeout(() => {
      socket.removeListener('message', messageHandler);
      reject(new Error(`STUN request timeout to ${serverHost}:${serverPort}`));
    }, timeoutMs);
    
    const messageHandler = (msg, rinfo) => {
        // Simple validation: Check if it looks like a STUN message
        if (msg.length < 20) return;

        // Check Transaction ID (RFC 5389 location: 8-19)
        // We compare the 12 bytes.
        const responseTransactionId = msg.slice(8, 20);
        
        if (responseTransactionId.equals(transactionId)) {
            // If we expect a different source (CHANGE-REQUEST), verify it
            if (expectDifferentSource) {
                // For CHANGE-REQUEST to succeed, response must come from different IP or port
                const sameIP = (rinfo.address === resolvedServerIP);
                const samePort = (rinfo.port === serverPort);
                
                if (sameIP && samePort) {
                    // Response from same source - not a valid CHANGE-REQUEST response
                    // Don't resolve - keep waiting for the real changed-source response
                    return;
                }
            }
            
            clearTimeout(timeout);
            socket.removeListener('message', messageHandler);
            try {
                const result = parseStunResponse(msg);
                // For Change Request tests, we might not get a Mapped Address if it's just a response
                // But usually Binding Response contains Mapped Address.
                // Even if parse fails, the fact we got a response is significant for Cone type detection.
                if (result) {
                    resolve(result);
                } else {
                     // Return empty object if we got a valid STUN packet but couldn't parse address
                     // (This counts as a success for reachability)
                    resolve({ raw: msg });
                }
            } catch (error) {
                reject(error);
            }
        }
    };
    
    socket.on('message', messageHandler);
    
    // Send to resolved IP, not hostname, to ensure consistent source tracking
    socket.send(requestBuffer, 0, requestBuffer.length, serverPort, resolvedServerIP, (err) => {
      if (err) {
        clearTimeout(timeout);
        socket.removeListener('message', messageHandler);
        reject(err);
      }
    });
  });
}

// Detect NAT type
async function detectNATType(socket = null) {
  return new Promise(async (resolve) => {
    const localIP = await getLocalIP();
    let ownSocket = false;
    
    if (!socket) {
      socket = dgram.createSocket('udp4');
      ownSocket = true;
    }
    
    const cleanup = () => {
        if (ownSocket) socket.close();
    };

    console.log(`Local Network IP: ${localIP}`);

    // Phase 1: Basic Connectivity & Symmetric Check
    // We need to bind if we just created the socket
    if (ownSocket) {
        socket.bind(0, '0.0.0.0');
        await new Promise(r => setTimeout(r, 100)); // wait for bind
    }
    
    const localPort = socket.address().port;
    console.log(`Local Port: ${localPort}`);

    let primaryResult = null;
    let mappingBehavior = 'Unknown';
    let portPreserved = false;
    
    // Test 1: Connect to Server 1
    try {
        primaryResult = await makeStunRequest(socket, STUN_SERVERS[0].host, STUN_SERVERS[0].port);
    } catch (e) {
        // Try backup server
        try {
             primaryResult = await makeStunRequest(socket, STUN_SERVERS[1].host, STUN_SERVERS[1].port);
        } catch (e2) {
            cleanup();
            return resolve({ type: 'UDP Blocked', reason: 'All STUN requests failed' });
        }
    }

    if (primaryResult.ip === localIP) {
        cleanup();
        return resolve({ type: 'Open Internet', reason: 'No NAT detected', public: primaryResult });
    }
    
    if (primaryResult.port === localPort) {
        portPreserved = true;
    }

    // Test 2: Check Mapping Behavior (Endpoint Independent vs Dependent)
    // Send to a different server
    try {
        const server2 = STUN_SERVERS[2]; // stun.stunprotocol.org
        const result2 = await makeStunRequest(socket, server2.host, server2.port);
        
        if (result2.ip === primaryResult.ip && result2.port === primaryResult.port) {
            mappingBehavior = 'Endpoint Independent';
        } else {
            mappingBehavior = 'Endpoint Dependent';
        }
        
    } catch (e) {
        // If second server fails, we can't determine mapping behavior easily
        // But we can try another one from the list
        try {
             const server2b = STUN_SERVERS[1]; // stun1.l.google.com
             const result2b = await makeStunRequest(socket, server2b.host, server2b.port);
             if (result2b.ip === primaryResult.ip && result2b.port === primaryResult.port) {
                mappingBehavior = 'Endpoint Independent';
            } else {
                mappingBehavior = 'Endpoint Dependent';
            }
        } catch (e2) {
            // Assuming Cone if we can't prove Symmetric, but it's risky.
            // If we only can talk to one server, we assume 'Unknown' or Cone.
            mappingBehavior = 'Endpoint Independent'; // Fallback
        }
    }

    if (mappingBehavior === 'Endpoint Dependent') {
        cleanup();
        return resolve({ 
            type: 'Symmetric NAT', 
            reason: 'Public IP/Port varies by destination',
            public: primaryResult 
        });
    }

    // Phase 2: Cone NAT Subtype Detection
    // We have "Endpoint Independent Mapping". 
    // Now we distinguish: Full Cone vs Restricted Cone vs Port Restricted Cone.
    // Requires sending CHANGE-REQUEST.
    
    let subtype = 'Port Restricted Cone NAT'; // Default / Most restrictive assumption
    let detectedSubtype = false;
    
    console.log('Detected Endpoint Independent Mapping. Probing for Cone Subtype...');

    for (const server of RFC3489_SERVERS) {
        try {
            // 1. Establish mapping with this specific server first
            // (We need to know the server accepts our packets before we ask it to change IP)
            await makeStunRequest(socket, server.host, server.port, [], 2000);
            
            // 2. Test for Full Cone: Change IP and Port
            // Attribute 0x0003 (CHANGE-REQUEST), Value 0x00000006 (Change IP | Change Port)
            const changeIpPort = Buffer.from([0, 0, 0, 6]);
            try {
                await makeStunRequest(socket, server.host, server.port, [{type: 0x0003, value: changeIpPort}], 2000, true);
                // If we get a response, it means we received a packet from a different IP/Port
                subtype = 'Full Cone NAT';
                detectedSubtype = true;
                break;
            } catch (e) {
                // Timeout: Not Full Cone (or server capability issue)
                // 3. Test for Restricted Cone: Change Port only
                // Value 0x00000002 (Change Port)
                const changePort = Buffer.from([0, 0, 0, 2]);
                try {
                     await makeStunRequest(socket, server.host, server.port, [{type: 0x0003, value: changePort}], 2000, true);
                     // If we get a response, it means we received a packet from Same IP, Different Port
                     subtype = 'Restricted Cone NAT';
                     detectedSubtype = true;
                     break;
                } catch (e2) {
                    // Timeout: Likely Port Restricted Cone
                    // We continue loop only if we think this server might be broken, 
                    // but we already verified connectivity.
                    // If connectivity worked but Change Request failed, it's likely the NAT blocking the changed response.
                    // So "Port Restricted" is the correct inference.
                    subtype = 'Port Restricted Cone NAT';
                    detectedSubtype = true;
                    break; 
                }
            }
        } catch (e) {
            // Server down or unreachable, try next
            continue;
        }
    }

    cleanup();
    
    resolve({
        type: subtype,
        reason: `Endpoint Independent Mapping. ${portPreserved ? 'Port Preserved.' : ''}`,
        public: primaryResult
    });
  });
}

async function main() {
  console.log('Starting STUN NAT Type Detection...');
  console.log('-----------------------------------');
  
  try {
    const result = await detectNATType();
    
    console.log('\n=== Final Result ===');
    console.log(`NAT Type:      ${result.type}`);
    console.log(`Reason:        ${result.reason}`);
    if (result.public) {
        console.log(`Public IP:     ${result.public.ip}`);
        console.log(`Public Port:   ${result.public.port}`);
    }
  } catch (error) {
    console.error('Error during detection:', error);
  }
}

main();
