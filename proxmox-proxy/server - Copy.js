import dotenv from 'dotenv';
dotenv.config();

import express from 'express';
import cors from 'cors';
import { createProxyMiddleware } from 'http-proxy-middleware';
import axios from 'axios';
import https from 'https';  // Import https
import { securityHeaders, apiLimiter } from './security.js';


const httpsAgent = new https.Agent({
  rejectUnauthorized: true  // Ensure SSL validation is performed
});

async function verifyProxmoxConnection() {
  console.log("******* Server Start :", new Date().toISOString(), " **********");
  console.log("DEBUG: ENV Variables Loaded:");
  console.log("PROXMOX_API_BASE:", process.env.PROXMOX_API_BASE);
  console.log("PROXMOX_NODE:", process.env.PROXMOX_NODE);
  console.log("PROXMOX_API_USER:", process.env.PROXMOX_API_USER);
  console.log("PROXMOX_API_TOKEN:", process.env.PROXMOX_API_TOKEN ? "Loaded" : "Not Set");

  if (!process.env.PROXMOX_API_BASE || !process.env.PROXMOX_NODE || !process.env.PROXMOX_API_TOKEN) {
    console.error("Missing required environment variables!");
    process.exit(1);
  }

  try {
    const authorizationHeader = `PVEAPIToken=${process.env.PROXMOX_API_USER}!${process.env.PROXMOX_API_TOKEN}`;

    const response = await axios.post(
      `${process.env.PROXMOX_API_BASE}/nodes/${process.env.PROXMOX_NODE}/qemu/104/vncproxy`,
      {},
      {
        httpsAgent: httpsAgent,
        headers: {
          Authorization: authorizationHeader,
          'Content-Type': 'application/json'
        }
      }
    );
    console.log('Proxmox connection verified:', response.data.data);
  } catch (error) {
    console.error('Proxmox connection failed:', error.response?.data || error.message);
    process.exit(1);
  }
}

const app = express();

// Security Middleware
app.use(securityHeaders);
app.use(cors({
  origin: process.env.FRONTEND_URL,
  credentials: true
}));
app.use(express.json());
app.use('/api', apiLimiter);

// WebSocket Proxy for VNC
app.use('/proxmox-ws', createProxyMiddleware({
  target: process.env.PROXMOX_HOST,
  changeOrigin: true,
  ws: true,
  logLevel: 'warn',
  pathRewrite: {
    '^/proxmox-ws': ''
  },
  onProxyReqWs: (proxyReq, req) => {
    proxyReq.setHeader('Authorization', process.env.PROXMOX_API_TOKEN);
  }
}));

// VNC Ticket Endpoint
app.get('/api/proxmox/vnc-ticket', async (req, res) => {
  try {
    const { vmId } = req.query;
    
    if (!vmId || !/^\d+$/.test(vmId)) {
      return res.status(400).json({ error: 'Invalid VM ID' });
    }

    const response = await axios.post(
      `${process.env.PROXMOX_API_BASE}/nodes/${process.env.PROXMOX_NODE}/qemu/${vmId}/vncproxy`,
      {},
      {
        httpsAgent: httpsAgent,
        headers: {
          Authorization: `PVEAPIToken=${process.env.PROXMOX_API_USER}!${process.env.PROXMOX_API_TOKEN}`,
          'Content-Type': 'application/json'
        }
      }
    );
   ///log Ticket
    console.log('Proxmox connection:', response.data.data);

    res.json({
      ticket: encodeURIComponent(response.data.data.ticket),
      port: response.data.data.port
    });

  } catch (error) {
    console.error('Proxy Error:', error.response?.data || error.message);
    res.status(500).json({ 
      error: 'Failed to get VNC ticket',
      details: error.response?.data?.errors || error.message
    });
  }
});


// Start the server only after verifying Proxmox connection
const PORT = process.env.PROXY_PORT || 3001;
verifyProxmoxConnection().then(() => {
  app.listen(PORT, () => {
      console.log(`Proxmox proxy service running on port ${PORT}`);
  });
});
