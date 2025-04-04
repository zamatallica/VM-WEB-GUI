const axios = require('axios');
const express = require('express');
const cors = require('cors');
const http = require('http');
const WebSocket = require('ws');
const { createProxyServer } = require('http-proxy');
const fs = require('fs');
const https = require('https');

const app = express();
const PORT = 3000;

// Proxmox API configuration
const PROXMOX_API = 'https://192.168.1.17:8006/api2/json';
const API_TOKEN = 'PVEAPIToken=VToWtDWlxH1MLbqz37L1ESiY';

// Pathto your Proxmox self-signed certificate
console.log('Using certificate file at: C:/certs/proxmox/prxmxhomesrvr.pem');
const cert = fs.readFileSync('C:/certs/proxmox/prxmxhomesrvr.pem');

// Create an https agent that trusts the certificate
const agent = new https.Agent({  
    ca: cert // Include the self-signed certificate here
});

app.use(cors());
app.use(express.json());

// Enable WebSocket
const proxy = createProxyServer({
    target: 'wss://192.168.1.17:8006', 
    ws: true
});

const server = http.createServer(app);

server.on('upgrade', (req, socket, head) => {
    if (req.url.startsWith('/websocket-proxy')) {
        proxy.ws(req, socket, head);
    }
});

// Route to fetch VNC ticket
app.get('/vnc-ticket', async (req, res) => {
    const { vmId } = req.query;

    if (!vmId) {
        return res.status(400).json({ error: 'Missing vmId parameter' });
    }

    try {
        // Use the axios agent here to ensure SSL certificate is trusted
        const response = await axios.post(
            `${PROXMOX_API}/nodes/prxmxhomesrvr/qemu/${vmId}/vncproxy`,
            {},
            { 
                headers: { Authorization: API_TOKEN },
                httpsAgent: agent  // Use the custom agent for trusted SSL connections
            }
        );
        res.json(response.data.data);
    } catch (error) {
        console.error('VNC proxy error:', error.response?.data || error.message);
        res.status(500).json({ error: 'VNC proxy failed' });
    }
});

// Start the server
server.listen(PORT, () => {
    console.log(`Server running with WebSocket support on http://localhost:${PORT}`);
});
