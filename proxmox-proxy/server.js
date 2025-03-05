import dotenv from 'dotenv';
dotenv.config();

import express from 'express';
import cors from 'cors';
import fs from 'fs';
import path from 'path';
import axios from 'axios';
import https from 'https';
import http from 'http';
import { WebSocketServer, WebSocket } from 'ws';
import { securityHeaders, apiLimiter } from './security.js';

// Load custom CA certificate (if provided)
let customCert = null;
const certPath = process.env.PROXMOX_CA_CERT_PATH || path.join(__dirname, 'pve-root-ca.pem');

if (fs.existsSync(certPath)) {
  console.log(` Using custom Proxmox CA certificate from: ${certPath}`);
  customCert = fs.readFileSync(certPath);
}

// Create HTTPS agent with better certificate handling
const agent = new https.Agent({
  rejectUnauthorized: customCert ? true : false, // Reject invalid certs only if custom CA is loaded
  ca: customCert || undefined,
});

async function verifyProxmoxConnection() {
  console.log("******* Server Start :", new Date().toISOString(), " **********");
  console.log("DEBUG: ENV Variables Loaded:");
  console.log("PROXMOX_API_BASE:", process.env.PROXMOX_API_BASE);
  console.log("PROXMOX_NODE:", process.env.PROXMOX_NODE);
  console.log("PROXMOX_API_USER:", process.env.PROXMOX_API_USER);
  console.log("PROXMOX_API_TOKEN:", process.env.PROXMOX_API_TOKEN ? "Loaded" : "Not Set");

  if (!process.env.PROXMOX_API_BASE || !process.env.PROXMOX_NODE || !process.env.PROXMOX_API_TOKEN) {
    console.error(" Missing required environment variables!");
    process.exit(1);
  }

  try {
    const response = await axios.post(
      `https://${process.env.PROXMOX_API_BASE}/nodes/${process.env.PROXMOX_NODE}/qemu/104/vncproxy`,
      { 'generate-password': 1, websocket: 1 }, // Added required payload
      {
        httpsAgent: agent,
        headers: {
          Authorization: `PVEAPIToken=${process.env.PROXMOX_API_USER}!${process.env.PROXMOX_API_TOKEN}`,
          'Content-Type': 'application/json',
        },
      }
    );

    console.log(' Proxmox connection verified:', response.data.data);
  } catch (error) {
    console.error(' Proxmox connection failed:', error.response?.data || error.message);
    console.error(' SSL Debug:', error.cause);
    process.exit(1);
  }
}

const app = express();
// Security Middleware
app.use(express.json());
app.use(cors({
  origin: process.env.FRONTEND_URL,
  credentials: true,
}));
app.use(securityHeaders);
app.use('/api', apiLimiter);
// Trust proxies (needed when using Nginx as a reverse proxy)
app.set('trust proxy', 1); // The '1' means trust the first proxy

const server = http.createServer(app);
// Create WebSocket server and attach it to the HTTP server
const wss = new WebSocketServer({ noServer: true });

// Handle WebSocket upgrade requests
server.on('upgrade', (request, socket, head) => {
  console.log(" Incoming WebSocket upgrade request:", request.url);

  // Check if the request is for the /proxmox-ws endpoint
  if (request.url.startsWith('/proxmox-ws')) {
          // Extract query parameters
          const urlParams = new URLSearchParams(request.url.split('?')[1]);
          const port = urlParams.get('port');
          const vncticket = urlParams.get('vncticket');
          const vmId = urlParams.get('vmId');
    
    console.log(" WebSocket upgrade request for /proxmox-ws");

    // Extract required parameters from the request
    const token = `PVEAPIToken=${process.env.PROXMOX_API_USER}!${process.env.PROXMOX_API_TOKEN}`;

    if (!port || !vncticket || !vmId) {
      console.error('Missing required WebSocket parameters');
      socket.destroy();
      return;
  }

    // Reconstruct the target WebSocket URL for Proxmox
    const targetUrl = `wss://${process.env.PROXMOX_HOST}/api2/json/nodes/${process.env.PROXMOX_NODE}/qemu/${vmId}/vncwebsocket?port=${port}&vncticket=${encodeURIComponent(vncticket)}`;
    console.log(" Forwarding WebSocket to:", targetUrl);

    // Create a WebSocket connection to Proxmox with the Authorization Header
    const wsClient = new WebSocket(targetUrl, {
      headers: { Authorization: token }, // Inject PVEAPIToken Header
      agent, // Use the custom HTTPS agent for SSL/TLS
    });

    // Pipe data between client and Proxmox WebSocket
    wsClient.on('open', () => {
      console.log(" Connected to Proxmox WebSocket!");
      wss.handleUpgrade(request, socket, head, (ws) => {
        wsClient.on('message', (data) => ws.send(data));
        ws.on('message', (data) => wsClient.send(data));
      });
    });

    wsClient.on('error', (err) => {
      console.error(" WebSocket Error:", err);
      socket.destroy();
    });

    wsClient.on('close', () => {
      console.log(" WebSocket Closed.");
    });
  } else {
    console.error(" Invalid WebSocket upgrade path:", request.url);
    socket.destroy();
  }
});

// Fallback HTTP GET handler for /proxmox-ws (optional, for debugging)
app.get('/proxmox-ws', (req, res) => {
  res.status(400).json({ error: 'This endpoint is for WebSocket connections only.' });
});

// VNC Ticket Endpoint
app.get('/api/proxmox/vnc-ticket', async (req, res) => {
  try {
    const { vmId } = req.query;

    if (!vmId || !/^\d+$/.test(vmId)) {
      return res.status(400).json({ error: 'Invalid VM ID' });
    }

    const response = await axios.post(
      `https://${process.env.PROXMOX_API_BASE}/nodes/${process.env.PROXMOX_NODE}/qemu/${vmId}/vncproxy`,
      { 'generate-password': 1, websocket: 1 }, // Added required payload
      {
        httpsAgent: agent,
        headers: {
          Authorization: `PVEAPIToken=${process.env.PROXMOX_API_USER}!${process.env.PROXMOX_API_TOKEN}`,
          'Content-Type': 'application/json',
        },
      }
    );

    console.log('Proxmox VNC Ticket:', response.data.data);
    console.log('URI encoded Ticket:', encodeURIComponent(response.data.data.ticket));

    res.json({
      ticket: encodeURIComponent(response.data.data.ticket),
      port: response.data.data.port,
      password: response.data.data.password,
    });
  } catch (error) {
    console.error(' Proxy Error:', error.response?.data || error.message);
    res.status(500).json({
      error: 'Failed to get VNC ticket',
      details: error.response?.data?.errors || error.message,
    });
  }
});

// Start the server only after verifying Proxmox connection
const PORT = process.env.PROXY_PORT || 3001;
verifyProxmoxConnection().then(() => {
  server.listen(PORT, '0.0.0.0', () => {
    console.log(` Proxmox proxy service running on port ${PORT}`);
  });
});