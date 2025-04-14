/**
 * SecureWise Signaling Server
 * 
 * This is a production-ready WebSocket server implementation for SecureWise
 * that handles device pairing, signaling, and WebRTC communication setup.
 * 
 * Usage:
 * 1. Install dependencies: npm install ws https fs
 * 2. Configure SSL certificates (required for production)
 * 3. Run: node signaling-server.js
 */

const https = require('https');
const http = require('http');
const fs = require('fs');
const WebSocket = require('ws');
const crypto = require('crypto');
const url = require('url');

// Configuration
const config = {
  // Server port configuration
  httpPort: process.env.HTTP_PORT || 3000,
  httpsPort: process.env.HTTPS_PORT || 8443,
  
  // SSL configuration (required for production)
  useSSL: process.env.USE_SSL === 'true' || false,
  sslCertPath: process.env.SSL_CERT_PATH || './certs/cert.pem',
  sslKeyPath: process.env.SSL_KEY_PATH || './certs/key.pem',
  
  // Server settings
  pingInterval: 30000, // 30 seconds
  pingTimeout: 10000,  // 10 seconds
  
  // Security settings
  maxConnectionsPerIP: 10,
  tokenSecret: process.env.TOKEN_SECRET || 'securewise-default-secret-change-me'
};

// Track active connections
const connections = new Map(); // deviceId -> WebSocket
const rooms = new Map();       // roomId -> Set of deviceIds
const ipConnections = new Map(); // IP -> count
const deviceInfo = new Map();  // deviceId -> { type, name, lastActivity, etc }

// Create server (HTTP or HTTPS depending on configuration)
let server;
if (config.useSSL) {
  try {
    const sslOptions = {
      cert: fs.readFileSync(config.sslCertPath),
      key: fs.readFileSync(config.sslKeyPath)
    };
    server = https.createServer(sslOptions);
    console.log('Created HTTPS server with SSL');
  } catch (error) {
    console.error('Error setting up SSL:', error.message);
    console.warn('Falling back to HTTP (not recommended for production)');
    server = http.createServer();
  }
} else {
  server = http.createServer();
  console.warn('Running in HTTP mode - not recommended for production');
}

// Set up HTTP response for health checks
server.on('request', (req, res) => {
  const parsedUrl = url.parse(req.url);
  const path = parsedUrl.pathname;
  
  if (path === '/health') {
    // Health check endpoint
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ 
      status: 'ok', 
      timestamp: Date.now(),
      connections: connections.size,
      rooms: rooms.size
    }));
  } else if (path === '/stats' && req.headers.authorization === `Bearer ${config.tokenSecret}`) {
    // Protected stats endpoint (requires token)
    const stats = {
      connections: connections.size,
      rooms: rooms.size,
      ipConnectionsCount: ipConnections.size,
      deviceTypes: {
        controller: [...deviceInfo.values()].filter(d => d.type === 'controller').length,
        authenticator: [...deviceInfo.values()].filter(d => d.type === 'authenticator').length
      }
    };
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(stats));
  } else {
    // All other paths
    res.writeHead(404);
    res.end('Not found');
  }
});

// Create WebSocket server
const wss = new WebSocket.Server({ server });

// Generate a unique ID
function generateId(prefix = '') {
  return `${prefix}${crypto.randomBytes(8).toString('hex')}`;
}

// Validate JSON message
function validateMessage(message) {
  try {
    const parsed = JSON.parse(message);
    // Basic validation of required fields
    if (!parsed.type || typeof parsed.type !== 'string') {
      return null;
    }
    if (!parsed.sender || typeof parsed.sender !== 'string') {
      return null;
    }
    return parsed;
  } catch (e) {
    return null;
  }
}

// Send a message to a specific device
function sendToDevice(deviceId, message) {
  const connection = connections.get(deviceId);
  if (connection && connection.readyState === WebSocket.OPEN) {
    try {
      connection.send(JSON.stringify(message));
      return true;
    } catch (error) {
      console.error(`Error sending to ${deviceId}:`, error.message);
      return false;
    }
  }
  return false;
}

// Broadcast to all devices in a room except sender
function broadcastToRoom(roomId, message, excludeDeviceId = null) {
  const room = rooms.get(roomId);
  if (!room) return 0;
  
  let sentCount = 0;
  for (const deviceId of room) {
    if (deviceId !== excludeDeviceId) {
      if (sendToDevice(deviceId, message)) {
        sentCount++;
      }
    }
  }
  return sentCount;
}

// Handle new WebSocket connection
wss.on('connection', (ws, req) => {
  let deviceId = null;
  let deviceType = null;
  let roomId = null;
  
  // Get client IP
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  
  // Rate limiting by IP
  const ipCount = ipConnections.get(ip) || 0;
  if (ipCount >= config.maxConnectionsPerIP) {
    console.warn(`Too many connections from IP: ${ip}`);
    ws.close(1008, 'Too many connections');
    return;
  }
  ipConnections.set(ip, ipCount + 1);
  
  // Connection is established
  console.log(`New connection from ${ip}`);
  
  // Send initial welcome message
  ws.send(JSON.stringify({
    type: 'server-info',
    data: {
      serverId: 'SecureWise-Signaling',
      timestamp: Date.now(),
      message: 'Connected to SecureWise signaling server'
    }
  }));
  
  // Set up ping/pong for connection monitoring
  ws.isAlive = true;
  ws.on('pong', () => {
    ws.isAlive = true;
  });
  
  // Handle incoming messages
  ws.on('message', (message) => {
    try {
      // Validate and parse the message
      const data = validateMessage(message);
      if (!data) {
        console.warn('Received invalid message format');
        return;
      }
      
      // Update last activity
      if (deviceId && deviceInfo.has(deviceId)) {
        const info = deviceInfo.get(deviceId);
        info.lastActivity = Date.now();
        deviceInfo.set(deviceId, info);
      }
      
      console.log(`Received ${data.type} from ${data.sender}`);
      
      // Handle different message types
      switch (data.type) {
        case 'register':
          // Register a new device
          deviceId = data.sender;
          deviceType = data.data?.isController ? 'controller' : 'authenticator';
          
          // Store connection
          connections.set(deviceId, ws);
          
          // Store device info
          deviceInfo.set(deviceId, {
            id: deviceId,
            type: deviceType,
            name: data.data?.deviceName || 'Unknown device',
            ip: ip,
            connected: Date.now(),
            lastActivity: Date.now()
          });
          
          // Confirm registration
          ws.send(JSON.stringify({
            type: 'register-success',
            sender: 'server',
            recipient: deviceId,
            data: { deviceId, timestamp: Date.now() },
            timestamp: Date.now()
          }));
          
          console.log(`Device registered: ${deviceId} (${deviceType})`);
          break;
          
        case 'device-discovery':
          // Request to discover available devices
          if (!deviceId) {
            console.warn('Unregistered device attempting discovery');
            break;
          }
          
          // For controllers looking for authenticators or vice versa
          const searchingFor = deviceType === 'controller' ? 'authenticator' : 'controller';
          
          // Find matching devices
          const availableDevices = [...deviceInfo.entries()]
            .filter(([id, info]) => 
              info.type === searchingFor && 
              id !== deviceId &&
              connections.has(id) &&
              connections.get(id).readyState === WebSocket.OPEN
            )
            .map(([id, info]) => ({
              id,
              name: info.name,
              type: info.type
            }));
          
          // Send list of available devices
          ws.send(JSON.stringify({
            type: 'device-list',
            sender: 'server',
            recipient: deviceId,
            data: { devices: availableDevices },
            timestamp: Date.now()
          }));
          break;
          
        case 'join-room':
          // Join a room (for pairing)
          if (!deviceId) {
            console.warn('Unregistered device attempting to join room');
            break;
          }
          
          // Get or create room
          roomId = data.data?.roomId || generateId('room-');
          if (!rooms.has(roomId)) {
            rooms.set(roomId, new Set());
          }
          
          // Add device to room
          rooms.get(roomId).add(deviceId);
          
          // Notify all devices in the room
          broadcastToRoom(roomId, {
            type: 'device-joined',
            sender: 'server',
            data: {
              deviceId,
              deviceType,
              roomId,
              deviceCount: rooms.get(roomId).size
            },
            timestamp: Date.now()
          });
          
          // Confirm room join
          ws.send(JSON.stringify({
            type: 'room-joined',
            sender: 'server',
            recipient: deviceId,
            data: { 
              roomId,
              deviceCount: rooms.get(roomId).size 
            },
            timestamp: Date.now()
          }));
          
          console.log(`Device ${deviceId} joined room ${roomId}`);
          break;
          
        case 'leave-room':
          // Leave current room
          if (roomId && rooms.has(roomId)) {
            rooms.get(roomId).delete(deviceId);
            
            // Notify others in the room
            broadcastToRoom(roomId, {
              type: 'device-left',
              sender: 'server',
              data: {
                deviceId,
                roomId,
                deviceCount: rooms.get(roomId).size
              },
              timestamp: Date.now()
            });
            
            // Clean up empty rooms
            if (rooms.get(roomId).size === 0) {
              rooms.delete(roomId);
              console.log(`Room ${roomId} deleted (empty)`);
            }
            
            roomId = null;
          }
          break;
          
        // WebRTC Signaling messages
        case 'offer':
        case 'answer':
        case 'ice-candidate':
          // Forward signaling messages to the target device
          if (!data.recipient) {
            console.warn(`Missing recipient in ${data.type} message`);
            break;
          }
          
          // Forward the message to the target
          sendToDevice(data.recipient, {
            type: data.type,
            sender: deviceId,
            recipient: data.recipient,
            data: data.data,
            timestamp: Date.now()
          });
          break;
          
        // Custom commands (used by the SecureWise app)
        case 'command':
          if (!data.recipient) {
            console.warn('Missing recipient in command message');
            break;
          }
          
          // Forward the command
          sendToDevice(data.recipient, {
            type: 'command',
            sender: deviceId,
            recipient: data.recipient,
            data: data.data,
            timestamp: Date.now()
          });
          break;
          
        default:
          console.warn(`Unknown message type: ${data.type}`);
      }
    } catch (error) {
      console.error('Error processing message:', error);
    }
  });
  
  // Handle WebSocket closure
  ws.on('close', () => {
    console.log(`Connection closed for ${deviceId || 'unknown device'}`);
    
    // Decrease IP connection count
    const ipCount = ipConnections.get(ip);
    if (ipCount > 1) {
      ipConnections.set(ip, ipCount - 1);
    } else {
      ipConnections.delete(ip);
    }
    
    // Clean up device connection
    if (deviceId) {
      connections.delete(deviceId);
      
      // Notify room members if in a room
      if (roomId && rooms.has(roomId)) {
        rooms.get(roomId).delete(deviceId);
        
        broadcastToRoom(roomId, {
          type: 'device-disconnected',
          sender: 'server',
          data: {
            deviceId,
            roomId
          },
          timestamp: Date.now()
        });
        
        // Clean up empty rooms
        if (rooms.get(roomId).size === 0) {
          rooms.delete(roomId);
        }
      }
      
      // Keep device info for a while (for reconnections)
      setTimeout(() => {
        if (!connections.has(deviceId)) {
          deviceInfo.delete(deviceId);
        }
      }, 5 * 60 * 1000); // 5 minutes
    }
  });
  
  // Handle errors
  ws.on('error', (error) => {
    console.error(`WebSocket error for ${deviceId || 'unknown device'}:`, error.message);
  });
});

// Check for dead connections (ping/pong)
const interval = setInterval(() => {
  wss.clients.forEach((ws) => {
    if (ws.isAlive === false) {
      console.log('Terminating dead connection');
      return ws.terminate();
    }
    
    ws.isAlive = false;
    ws.ping(() => {});
  });
}, config.pingInterval);

// Clean up on server shutdown
wss.on('close', () => {
  clearInterval(interval);
});

// Start the server on both HTTP and HTTPS (if configured)
server.listen(config.useSSL ? config.httpsPort : config.httpPort, () => {
  console.log(`SecureWise Signaling Server running on port ${config.useSSL ? config.httpsPort : config.httpPort} (${config.useSSL ? 'HTTPS' : 'HTTP'} mode)`);
});

// Create a simple HTTP server for redirecting to HTTPS if both are enabled
if (config.useSSL && config.httpPort !== config.httpsPort) {
  const redirectServer = http.createServer((req, res) => {
    const host = req.headers.host?.split(':')[0] || 'localhost';
    res.writeHead(301, { 'Location': `https://${host}:${config.httpsPort}${req.url}` });
    res.end();
  });
  
  redirectServer.listen(config.httpPort, () => {
    console.log(`HTTP redirect server running on port ${config.httpPort}`);
  });
}

process.on('SIGINT', () => {
  console.log('Shutting down signaling server...');
  server.close(() => {
    console.log('Server shut down.');
    process.exit(0);
  });
});
