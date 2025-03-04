const axios = require('axios');
const https = require('https');

// Create an https agent to ignore certificate errors (ONLY for local testing)
const agent = new https.Agent({ rejectUnauthorized: false });

const response = await axios.post(
    `${PROXMOX_API}/nodes/prxmxhomesrvr/qemu/${vmId}/vncproxy`,
    {},
    { 
        headers: { Authorization: API_TOKEN },
        httpsAgent: agent 
    }
);
