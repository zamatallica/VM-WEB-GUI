/* =====================================================================================
   File: main.js
   Author: Alejandro Escobedo
   Verion: 
                3/22/2025 Initial Created module js for main web gui routines.
   -------------------------------------------------------------------
   Central logic for VNC interaction, Proxmox integration, and UI behavior.
   This file contains:
   - VNC connection setup with noVNC
   - Clipboard and fullscreen controls
   - Sidebar toggle behavior
   - User logout and session handling
   - Dynamic updates to VM Info Panel and charts
   - security settings
   Make sure this file loads *after* the DOM is ready.
====================================================================================== */


// Security Configuration
       const SECURITY = {
        maxAttempts: 5,  // Maximum number of failed attempts
        lockoutTime: 300000  // Lockout time in milliseconds (5 minutes)
    };

    let failedAttempts = 0;

    async function attemptLogin() {
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        const errorElement = document.getElementById('loginError');

        try {
            const response = await fetch('/api/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                },
                credentials: 'include',  // Include cookies in the request
                body: JSON.stringify({
                    username: username,
                    password: password
                })
            });

            const data = await response.json();

            if (response.ok && data.success) {
                resetLoginState();
                document.getElementById('username').value="";
                document.getElementById('password').value="";
                document.getElementById('username-display').textContent = username.toLowerCase() ;
                document.getElementById('loginContainer').classList.add('hidden');
                document.getElementById('mainInterface').classList.remove('hidden');
                document.getElementById('mainInterface_right').classList.remove('hidden');
                document.getElementById('status').textContent = "";
                getUserProfileInfo();
                populateVMsDropDown();
                cleanupVMInfoPanels();
            } else {
                handleFailedAttempt(data.message || "Authentication failed");
            }
        } catch (error) {
            showError("Service unavailable");
            console.error('Login error:', error);
        }
    }

    function handleFailedAttempt(message) {
        failedAttempts++;
        document.getElementById('attemptCount').textContent = failedAttempts;
        
        if (failedAttempts >= SECURITY.maxAttempts) {
            disableLoginForm();
            showError("Account locked - too many failed attempts");
            setTimeout(enableLoginForm, SECURITY.lockoutTime);
        } else {
            showError(message || "Invalid credentials");
        }
    }

    function resetLoginState() {
        failedAttempts = 0;
        document.getElementById('attemptCount').textContent = '0';
        document.getElementById('loginError').textContent = '';
    }

    function showError(message) {
        const errorElement = document.getElementById('loginError');
        errorElement.textContent = message;
        setTimeout(() => errorElement.textContent = '', 5000);
    }

    function disableLoginForm() {
        document.getElementById('loginForm').style.opacity = '0.5';
        document.getElementById('loginForm').querySelectorAll('input, button').forEach(el => {
            el.disabled = true;
        });
    }

    function enableLoginForm() {
        document.getElementById('loginForm').style.opacity = '1';
        document.getElementById('loginForm').querySelectorAll('input, button').forEach(el => {
            el.disabled = false;
        });
        resetLoginState();
    }

//Global Current VM connected
currentVM = null;

// Proxmox connection logic
let vncClient = null;

async function connectToVM() {
const vmSelect = document.getElementById('vmSelect');
const status = document.getElementById('status');
const vmId = vmSelect.value;

if (!vmId) {
    status.textContent = "Please select a VM first!";
    return;
}

try {
    //Set the Current connected VM
    currentVM = vmId;

    // Get VNC ticket from backend
    const response = await fetch(`/api/proxmox/vnc-ticket?vmId=${vmId}`, {
        method: 'GET',
        credentials: 'include'
    });

    if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
    }

    const data = await response.json();
    console.log("Generated VNC Ticket:", data);

    // Build WebSocket URL (use backend proxy)
    const wsUrl = `wss://${window.location.hostname}/proxmox-ws?port=${data.port}&vncticket=${data.ticket}&vmId=${vmId}`;
    console.log("Connecting to VNC WebSocket:", wsUrl);

    // Ensure RFB is loaded before connecting
    if (typeof window.RFB === "undefined") {
        console.error(" RFB not loaded properly!");
        return;
    }

    // Clean up existing VNC client
    if (vncClient) {
        vncClient.disconnect();
        vncClient = null;
        vncContainer.classList.remove("connected", "bad-disconnect","disconnecting");
    }

    // Initialize the VNC client
    const vncContainer = document.getElementById('vnc-container');
    vncClient = new window.RFB(vncContainer, wsUrl, {
        wsProtocols: ['binary'], // Ensure binary protocol is used
    });
    console.log("Using VNC password as credentials:",data.password);

    // Event listeners for VNC client
    vncClient.addEventListener('connect', () => {
        status.textContent = 'Connected!';
    //  Enable dynamic settings
        vncClient.scaleViewport    = true;   // Auto-scale VNC view
        vncClient.clipViewport     = true;    // Clip viewport to the container size
        vncClient.resizeSession = true;  // Auto-resize to fit
        vncClient.qualityLevel     = 9;       // Set quality level (0-9, higher is better)
        vncClient.compressionLevel = 2;   // Set compression (0-9, lower is better)  
        if (vncContainer) {
            vncContainer.classList.remove("connected", "bad-disconnect", "disconnecting");
        }
        vncContainer.classList.add("connected");

    });

    // Enable clipboard support
    vncClient.addEventListener("clipboard", (event) => {
    if (event.detail && event.detail.text) {
        navigator.clipboard.wristeText(event.detail.text)
            .then(() => console.log("Clipboard copied from VNC: ", event.detail.text))
            .catch(err => console.error("Clipboard copy failed:", err));
    }
    });     

    // Copy Clipboard
    vncClient.copyToClipboard = function () {
        navigator.clipboard.readText()
            .then(text => {
                vncClient.clipboardPasteFrom(text);
                Console.log("Clipboard sent to VM:", text);
    })
    .catch(err => console.error("Failed to read clipboard:", err));
    }

    // Sidebar Toggle
    window.toggleSidebar = function () {
        document.body.classList.toggle("sidebar-open");
        if( document.getElementById("sidebar-toggle").textContent == ">"){
           document.getElementById("sidebar-toggle").textContent="<";
        }  else {
            document.getElementById("sidebar-toggle").textContent=">";
        }
    };

    // Fullscreen Mode
    window.toggleFullscreen = function () {
        if (vncContainer.requestFullscreen) {
            vncContainer.requestFullscreen();
        } else if (vncContainer.mozRequestFullScreen) { // Firefox
            vncContainer.mozRequestFullScreen();
        } else if (vncContainer.webkitRequestFullscreen) { // Chrome, Safari, Opera
            vncContainer.webkitRequestFullscreen();
        } else if (vncContainer.msRequestFullscreen) { // IE/Edge
            vncContainer.msRequestFullscreen();
        }
    };

    // Toggle Scaling
    window.toggleScaling = function () {
        if (vncClient) {
            vncClient.scaleViewport = !vncClient.scaleViewport;
            alert("Scaling: " + (vncClient.scaleViewport ? "Enabled" : "Disabled"));
        } else {
            console.error("VNC Client is not initialized");
        }
    };

    // Send Ctrl+Alt+Del
    window.sendCtrlAltDel = function () {
        if (vncClient) {
            vncClient.sendCtrlAltDel();
        } else {
            console.error("VNC Client is not initialized");
        }
    };

    vncClient.addEventListener('credentialsrequired', () => {
        console.log("Credentials required for VNC connection.");
        vncClient.sendCredentials({
            password: data.ticket // Send the VNC ticket as the password
        });
    });

    vncClient.addEventListener('credentialsrequired', () => {
        console.log("Credentials required for VNC connection.");
        vncClient.sendCredentials({
            password: data.password, // Send the VNC password
        });
    });

    vncClient.addEventListener('disconnect', (e) => {
        status.textContent = `Disconnected: ${e.detail.clean ? 'Clean' : 'Dirty'} disconnect`;
        vncContainer.classList.remove("connected", "bad-disconnect","disconnecting");
        vncContainer.classList.add("disconnecting");// Indicate disconnection
    }); 

    } catch (error) {
        status.textContent = `Connection failed: ${error.message}`;
        vncContainer.classList.add("bad-disconnect");
    }
}

async function logout() {
    try {
        const response = await fetch('/api/logout', {
            method: 'POST',
            credentials: 'include'  // Include cookies in the request
        });

        if (response.ok) {
            document.getElementById('vmSelect').value = "";
            document.getElementById('username-display').textContent = "";
            document.getElementById('loginContainer').classList.remove('hidden');
            document.getElementById('mainInterface').classList.add('hidden');
            document.getElementById('mainInterface_right').classList.add('hidden');
            document.getElementById('vmSelect').value = "";
            document.getElementById('status').textContent = "";

            // Stop Panel updates
            currentVM = null;
            startAutoUpdate();

            if (updateInterval) {
                clearInterval(updateInterval);
                updateInterval = null;
            }
            //Cleanup VM Info Panel
            cleanupVMInfoPanels();

            const vncContainer = document.getElementById('vnc-container');
            // Clean up existing VNC client
            if (vncClient) {
                vncClient.disconnect();
                vncClient = null;
                currentVM = null;
                if (vncContainer) {
                    vncContainer.classList.remove("connected", "bad-disconnect", "disconnecting");
                }
                document.getElementById('username-display').textContent = "";
                console.log("NOW LOGGING OUT USER");
            }
        }    
    } catch (error) {
        console.error('Logout error:', error);
    }
}
//-------- GUI FUNCTIONS
function toggleUserMenu() {
        document.querySelector('.user-menu-wrapper').classList.toggle('active');
    }

function sendKey(key) {
    window.sendKey = function () {
        if (vncClient) {
            vncClient.sendKey(key);
        } else {
            console.error("VNC Client is not initialized");
        }
    };
}
    // Close dropdown if clicked outside
    document.addEventListener('click', function(event) {
        const userMenu = document.querySelector('.user-menu-wrapper');
        if (!userMenu.contains(event.target)) {
            userMenu.classList.remove('active');
        }
});


// Function to format uptime in days, hours, minutes, and seconds
function formatUptime(seconds) {
        const days = Math.floor(seconds / 86400); // 86400 seconds in a day
        seconds %= 86400; // Get remaining seconds after removing days

        const hours = Math.floor(seconds / 3600); // 3600 seconds in an hour
        seconds %= 3600; // Get remaining seconds after removing hours

        const minutes = Math.floor(seconds / 60); // 60 seconds in a minute
        seconds %= 60; // Remaining seconds

        return `${days} Days ${hours}:${minutes}:${seconds}`;
}

/*CPU Graph Initialize
  Store the Chart instance globally to avoid re-creating it  */

let cpuChart;
let cpuData = {
labels: Array(20).fill(""), // 20 empty slots
datasets: [
    {
        label: "CPU (%)",
        borderColor: "rgb(243, 130, 37)",
        backgroundColor: "rgb(229, 137, 9,.2)",
        borderWidth: 1,
        fill: true,
        tension: .3, // Makes the line smooth
        pointRadius: 0, // No dots on the graph
        pointHoverRadius: 0, // No dots on hover
        data: Array(20).fill(0) // Initial data
    },
    {
        label: "MEM (%)",
        borderColor: "rgb(131, 23, 255)",
        backgroundColor: "rgb(131, 23, 255,.2)",
        borderWidth: 1,
        fill: false,
        tension: 0.3, 
        pointRadius: 0, 
        pointHoverRadius: 0, 
        data: Array(20).fill(0) 
    }
]
};

// Ensure the chart is created **only once**
function createCpuChart() {
let canvas = document.getElementById("cpuUsageChart");
if (!canvas) {
    console.error("Canvas element not found!");
    return;
}

let ctx = canvas.getContext("2d");

if (!cpuChart) { // **Create chart only if it doesn't exist**
    cpuChart = new Chart(ctx, {
        type: "line",
        data: cpuData,
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: { duration: 100 }, // Smooth animation
            scales: {
                x: { display: false },
                y: { beginAtZero: true, 
                    max: 100,
                    grid: {
                    color: "rgba(255, 255, 255, 0.1)", // Change Y-axis grid color
                    borderColor: "rgba(255, 255, 255, 0.5)" // Border line color
                    }
                 }
                 
            }
        }
    });
}
}

async function populateVMInfoPanel(vmId) {
if (!vmId ) {
    //nothing to do
    return;
}
try {
    // Fetch VM info from backend
    const response = await fetch(`/api/proxmox/vm-InfoPanel?vmId=${vmId}`, {
        method: 'GET',
        credentials: 'include'
    });

    if (!response.ok) {
        throw new Error(`HTTP error! Status: ${response.status}`);
    }

    const data = await response.json();

    // Check if API response contains the expected keys
    if (data.vmstatus) {
        const bytetoGB = 0.000000000931322574615478515625
        const formattedUptime = formatUptime(data.uptime);
        const cpuUsagePercent = Math.min(Math.max(data.cpuusage * 100, 0), 100); // Ensure 0-100 range
        let memUsagePercent = Math.min(Math.max((data.memusage/data.maxmem) * 100, 0), 100); // Ensure 0-100 range
        const cpuUsagePercentText  = `${Math.round(cpuUsagePercent)}`;
    

        // Update UI elements 
        document.getElementById('vm-infobox-uptime').textContent = `Uptime: ${formattedUptime}`;
        document.querySelector('.vm-infobox-content-statusbar-CPU').style.width = `${cpuUsagePercent}%`;
        document.getElementById('vm-infobox-CPU-usage').textContent = `${cpuUsagePercentText}% of ${data.cpus} CPUs`;
        document.getElementById('vm-infobox-OSname').textContent = `OS: ${data.os}`;
        document.getElementById('vm-infobox-header-text').textContent = `${data.name}`;
        document.getElementById('vm-infobox-vmstatus').textContent = `${data.vmstatus}`;
        document.getElementById('vm-infobox-MEM-usage').textContent = `${Math.round(memUsagePercent)}% (${ (data.memusage * bytetoGB).toFixed(2) }GB/${ Math.round(data.maxmem * bytetoGB) }GB)`;
        document.querySelector('.vm-infobox-content-statusbar-MEM').style.width = `${memUsagePercent}%`;
        document.getElementById('vm-infobox-Ipaddress').textContent = `${data.ipv4}`;
        document.getElementById('vm-infobox-vmhostname').textContent = `Hostname: ${data.hostname}`;
        document.getElementById('vm-infobox-user-header-cpu-mem').textContent = `CPU: ${Math.round(cpuUsagePercent)}% | MEM: ${Math.round(memUsagePercent)}%`

        //HIGH CPU Usage Shenanigans
        const cpuBar = document.querySelector('.vm-infobox-content-statusbar-CPU');

        // Set bar width
        cpuBar.style.width = `${cpuUsagePercent}%`;

        // Calculate glow intensity (adjust scaling as needed)
        const glowIntensity = Math.min(cpuUsagePercent / 100, 1); // 0.0 to 1.0
        const glowOpacity = 0.3 + glowIntensity * 0.7; // from 0.3 to 1.0

        cpuBar.style.boxShadow = `0 0 ${4 + glowIntensity * 16}px ${1 + glowIntensity * 4}px rgba(255, 119, 56, ${glowOpacity})`;

        // Ensure CPU chart is initialize
        if (!cpuChart) {
            createCpuChart();
        }

        // Update CPU graph 
        if  (cpuChart && cpuChart.data && cpuChart.data.datasets.length >= 2) {
            cpuChart.data.datasets[0].data.push(cpuUsagePercent);
            cpuChart.data.datasets[1].data.push(memUsagePercent);
            cpuChart.data.labels.push(""); // Maintain label count

            // Limit data points to 20 
            if (cpuChart.data.datasets[0].data.length > 20) {
                cpuChart.data.datasets[0].data.shift(); // Remove oldest
                cpuChart.data.datasets[1].data.shift(); // Remove oldest
                cpuChart.data.labels.shift();
            }

            cpuChart.update("none"); // Refresh 

            //CPU and MEM usage bars 
            const cpuBar = document.querySelector('.vm-infobox-content-statusbar-CPU');
            const memBar = document.querySelector('.vm-infobox-content-statusbar-MEM');

            // Set the width visually
            cpuBar.style.width = `${cpuUsagePercent}%`;
            memBar.style.width = `${memUsagePercent}%`;
            
            // Set the dynamic glow always
            let glowIntensity = cpuUsagePercent / 100;
            let glowOpacity = Math.min(glowIntensity + 0.1, 1);

            if(memUsagePercent < 85){ //mem threshold 
                memUsagePercent = memUsagePercent - 40
            }
            let memglowIntensity = memUsagePercent / 100; 
            let memglowOpacity = Math.min(memglowIntensity + 0.1, 1);

            //CPU Bar
            const red = 255;
            const green = Math.floor(119 - (glowIntensity * 119)); // Goes from orange (119) to 0
            const blue = Math.floor(56 - (glowIntensity * 56));     // Slight darkening
            
            cpuBar.style.boxShadow = `0 0 ${4 + glowIntensity * 16}px ${1 + glowIntensity * 4}px rgba(${red}, ${green}, ${blue}, ${glowOpacity})`;
            
            //Mem Bar
            const mgreen = Math.floor(119 - (memglowIntensity * 119)); // Goes from orange (119) to 0
            const mblue = Math.floor(56 - (memglowIntensity * 56));     // Slight darkening
            
            memBar.style.boxShadow = `0 0 ${4 + memglowIntensity * 16}px ${1 + memglowIntensity * 4}px rgba(${red}, ${mgreen}, ${mblue}, ${memglowOpacity})`;
            
        }

        let whatOS = data.os.toLowerCase();
        let fpath = document.getElementById('vm-infobox-OS-icon').src || "/static/images/os_default.png";
        let rpath = fpath.split("/").pop();
        let osIcon = "/static/images/os_default.png";
        let lnxDistros = [
                            "linux", "ubuntu", "debian", "red hat", "centos", "fedora",
                            "arch", "manjaro", "opensuse", "pop!_os", "elementary os",
                            "zorin", "kali", "parrot", "rocky", "almalinux", "mint",
                            "gentoo", "slackware", "clear linux", "deepin", "mx linux",
                            "raspbian", "raspberry pi os", "suse"
                        ];
        let isLinuxBased = lnxDistros.some(distros => whatOS.includes(distros));
        //Display Icon according to the vm OS, kinda.
        if (whatOS.search("windows") >= 0){
            osIcon="/static/images/os_windows.png";
        }else if (isLinuxBased){
            osIcon="/static/images/os_linux.png";
        }else if (whatOS.search("mac") >= 0){
            osIcon="/static/images/os_mac.png";
        }else{
            osIcon = "/static/images/os_default.png";
        }
        //We dont want to keep refreshin the Icon unlike the data.
        if(rpath != osIcon.split("/").pop()){
            document.getElementById('vm-infobox-OS-icon').src= osIcon;
            console.log(osIcon.split("/").pop());            
        }
    
    } else {
        console.error("Invalid response from API:", data);
    }
} catch (error) {
    console.error("Fetch Error:", error);
}
}

let updateInterval = null; // Store the interval ID

// Function to start auto-refreshing the VM info panel
function startAutoUpdate() {
if (!currentVM) {

        // Clear dropdown and reset info panel
        document.getElementById('vmSelect').value = "";
        cleanupVMInfoPanels();
  
        // Clear chart data before destroy
        if (cpuChart) {
            cpuChart.data.datasets.forEach(ds => ds.data = []);
            cpuChart.data.labels = [];
            cpuChart.update(); // Optional: reflect before destroy
            cpuChart.destroy();
            cpuChart = null;
        }
   

        // Stop interval updates if running
        if (updateInterval) {
            clearInterval(updateInterval);
            updateInterval = null;
        }

        return;
}

// Stop any previous interval before starting a new one
if (updateInterval) {
    clearInterval(updateInterval);
}

// Ensure CPU chart is initialized
if (!cpuChart) {
    createCpuChart();
}


// Immediately update UI once, then refresh every 1 seconds
populateVMInfoPanel(currentVM);
updateInterval = setInterval(() => populateVMInfoPanel(currentVM), 1000);
}

// Get the selected VM ID and start the auto-update process
document.addEventListener("DOMContentLoaded", function () {
const vmSelectBtn = document.getElementById("vmBtnSelect");
const vmSelect = document.getElementById("vmSelect");

//---------  CALLS PANEL POPULATE FUNCTIONS------------------------------------------------------------
if (vmSelect && vmSelectBtn) {
    // Listen for VM selection change
    vmSelectBtn.addEventListener("click", function () {
        const selectedVM = vmSelect.value;
        startAutoUpdate(selectedVM);
        populateVMUserLoginPanel(selectedVM)
    });

    // Start auto-update with the initially selected VM
    startAutoUpdate(vmSelect.value);
}
});

    //INFO PANEL Repositioning(!!! WARNING THE SHITIEST CODE YOU'LL EVER SEEN BELOW!!!!!!)
    document.addEventListener("DOMContentLoaded", function () {
    const vmInfoToggle = document.getElementById("vm-infobox-toggle");
    const vmInfoContent = document.querySelector(".vm-infobox-content");
    const userPanel = document.querySelector(".vm-infobox-user-container");
    const uservmsPanel = document.querySelector(".vm-infobox-uservms-container");
    const vmCredentialsToggle = document.getElementById("vm-infobox-toggle-user");

    function adjustUserPanelPosition() {
        // Get the height of the VM info content
        const contentHeight = vmInfoContent.scrollHeight; 
        
        if (vmInfoToggle.checked) {
            userPanel.style.top = "100px"; // Adjust as needed
            uservmsPanel.style.top = `${userPanel.scrollHeight + 110}px`;
            if(vmCredentialsToggle.checked){
                uservmsPanel.style.top = "135px";
            }
        } else {
                 userPanel.style.top = `${contentHeight + 480}px`; //Initial Position, Initializes user credential panel on this position.
                if (contentHeight != 0){
                    userPanel.style.top = `${contentHeight + 110}px`; // Default collapsed position
                }
                const credentialsHeight = userPanel.scrollHeight; 
                if (vmCredentialsToggle.checked) {
                    uservmsPanel.style.top = `${credentialsHeight + 150}px`;
                } else {
                    uservmsPanel.style.top = `${credentialsHeight+ 810}px`;
                    if (credentialsHeight != 0){
                        uservmsPanel.style.top = `${credentialsHeight +contentHeight+ 125}px`;
                    }
                }
    
        }
    }
    // Listen for changes in the checkbox toggle
    vmInfoToggle.addEventListener("change", adjustUserPanelPosition);
    vmCredentialsToggle.addEventListener("change", adjustUserPanelPosition);

    //Not my proudest moment,  it's hacky but it gets the job done "( – ⌓ – )=3 (4 hrs trying to get it done the "right way" was more than enough to break my will.)
    const targetDiv = document.getElementById("Credentials_Dataset");
    //We listen for changes on the size of the vm user credentials result set so we triger the panel size adjustemen dynamically.
    const observer = new MutationObserver((mutationsList, observer) => {
    for (let mutation of mutationsList) {
        adjustUserPanelPosition();
    }
    });
    // Observer config – adjust as needed
    observer.observe(targetDiv, {
    childList: true,
    });
    // Run the function once to set the initial state
    adjustUserPanelPosition();
});

function cleanupVMInfoPanels() {
    document.getElementById('vm-infobox-uptime').textContent = "Uptime:";
    document.querySelector('.vm-infobox-content-statusbar-CPU').style.width = "0%";
    document.querySelector('.vm-infobox-content-statusbar-CPU').style.boxShadow = "0 0 4px 1px rgb(255, 119, 56)"; /* Default glow */
    document.getElementById('vm-infobox-CPU-usage').textContent = "";
    document.getElementById('vm-infobox-OSname').textContent = "OS:";
    document.getElementById('vm-infobox-header-text').textContent = "VM Machine Info";
    document.getElementById('vm-infobox-vmstatus').textContent = "";
    document.getElementById('vm-infobox-MEM-usage').textContent = "";
    document.querySelector('.vm-infobox-content-statusbar-MEM').style.width = "0%";
    document.querySelector('.vm-infobox-content-statusbar-MEM').style.boxShadow = "0 0 4px 1px rgb(255, 119, 56)"; /* Default glow */
    document.getElementById('vm-infobox-Ipaddress').textContent = "0.0.0.0";
    document.getElementById('vm-infobox-vmhostname').textContent = "Hostname:";
    document.getElementById('vm-infobox-user-header-cpu-mem').textContent = "";
    document.getElementById('vm-infobox-OS-icon').src= "/static/images/os_default.png";
    const parent_div = document.getElementById("Credentials_Dataset");
    parent_div.innerHTML = ""; // Clear previous entries if needed

    currentPage=0 //reset current page on Search Panel
    const parent_div2 = document.getElementById("vm_search_dataset");
    parent_div2.innerHTML = ""; // Clear previous entries 
    PupulateUserVMAdministration(); //Repopulate if inital page was first page so it wont appear cleaned up upon login back.



    // Clear chart data before destroy
    if (cpuChart) {
        cpuChart.data.datasets.forEach(ds => ds.data = []);
        cpuChart.data.labels = [];
        cpuChart.update(); // Optional: reflect before destroy
        cpuChart.destroy();
        cpuChart = null;
    }


    // Stop interval updates if running
    if (updateInterval) {
        clearInterval(updateInterval);
        updateInterval = null;
    }
}

function showToast(message) {
    const toast = document.getElementById('status');
    const previousMsg =  document.getElementById('status').textContent
    toast.textContent = message;
    toast.classList.add("shake")

    setTimeout(() => {
        toast.classList.remove("shake");
        if( previousMsg !=='Password copied to clipboard !!'){
        toast.textContent = previousMsg;
        }
    }, 3000);
}

let isVisibleMap = {};
let hideTimeout = null;

function togglePassword(id) {
    const pwInput = document.getElementById(id);

    if (!isVisibleMap[id]) {
        pwInput.type = "text";
        isVisibleMap[id] = true;

        // Copy password to clipboard
        navigator.clipboard.writeText(pwInput.value)
            .then(() => showToast("Password copied to clipboard !!"))
            .catch(err => console.error("Clipboard copy failed:", err));

            setTimeout(() => {
                const allInputs = document.querySelectorAll('.login-input-info-data-pw');
                allInputs.forEach(input => input.type = "password");
    
                // Clear visibility flags
                for (let key in isVisibleMap) {
                    isVisibleMap[key] = false;
                }
            }, 5000);
        } else {
            pwInput.type = "password";
            isVisibleMap[id] = false;
        }
    }


const vm_login_credentials_ds_cache = [];//Reuse dataset for filtering later on

async function populateVMUserLoginPanel(vmId) {
    if (!vmId ) {
        //nothing to do
        return;
    }
    try {
        // Fetch VM info from backend
        const response = await fetch(`api/get-vm-user-credentials?vm_id=${vmId}`, {
            method: 'GET',
            credentials: 'include'
        });
    
        if (!response.ok) {
            throw new Error(`HTTP error! Status: ${response.status}`);
        }
    
        const data = await response.json();
        const credentials_list = data["credentials_list"]
        vm_login_credentials_ds_cache.length = 0;
        vm_login_credentials_ds_cache.push(...credentials_list);
        console.log("Credentials:",vm_login_credentials_ds_cache)
    
        // Check if API response contains the expected keys
        if (data.success) {
            const parent_div = document.getElementById("Credentials_Dataset");
            parent_div.innerHTML = ""; // Clear previous entries if needed

            credentials_list.forEach((credential, index) => {
                let iDiv= document.createElement('div');
                let lastLogin = new Date(credential.vm_last_logon);
                let formattedLogin = lastLogin.toLocaleString();
                    iDiv.className='vm-infobox-content-user-login-data';
                let bgColor = `vm-alternate-color-${index%2}`;

                    iDiv.innerHTML = ` <div  class="vm-infobox-content-login-info-data ${bgColor}">${credential.credential_username}</div>
                                       <div  class="vm-infobox-content-login-info-data ${bgColor}"><button type="button" class="vm-info-show-pw tooltip" onclick="togglePassword('login-input-info-data-pw-${index}')"><img class="view-ico" src='static/images/view-ico.svg') }}"><span class="tooltiptext">Copy password to clipboard</span></button><input type="password" id="login-input-info-data-pw-${index}" class="login-input-info-data-pw" value="${credential.vm_user_password}" readonly></div>
                                       <div  class="vm-infobox-content-login-info-data ${bgColor}">${credential.domain_name}</div>
                                       <div  class="vm-infobox-content-login-info-login ${bgColor}">${formattedLogin}</div>
                    `;
                    parent_div.appendChild(iDiv);
            });
        
        }
    } catch (error) {
        console.error("Fetch Error:", error);
    }      
    
}
//Reuses cached data from vm_login_credentials_ds_cache
function FilterVMUserLoginPanel(filter) {
    try {
        let credentials_list_filtered = [];

        if(filter==1){
         credentials_list_filtered = vm_login_credentials_ds_cache.filter(credential =>
            credential.domain_name === ".local"
        );
        }else if (filter==0){
         credentials_list_filtered = vm_login_credentials_ds_cache.filter(credential =>
            credential.domain_name !== ".local"
        );
        }else{
            credentials_list_filtered = vm_login_credentials_ds_cache
        }
        console.log("Filtered list:", credentials_list_filtered)
        const parent_div = document.getElementById("Credentials_Dataset");
        parent_div.innerHTML = ""; // Clear previous entries


        credentials_list_filtered.forEach((credential, index) => {
            let iDiv= document.createElement('div');
            let lastLogin = new Date(credential.vm_last_logon);
            let formattedLogin = lastLogin.toLocaleString();
                iDiv.className='vm-infobox-content-user-login-data';
            let bgColor = `vm-alternate-color-${index%2}`;
                iDiv.innerHTML = ` <div  class="vm-infobox-content-login-info-data ${bgColor}">${credential.credential_username}</div>
                                   <div  class="vm-infobox-content-login-info-data ${bgColor}"><button type="button" class="vm-info-show-pw tooltip" onclick="togglePassword('login-input-info-data-pw-${index}')"><img class="view-ico" src='static/images/view-ico.svg') }}"><span class="tooltiptext">Copy password to clipboard</span></button><input type="password" id="login-input-info-data-pw-${index}" class="login-input-info-data-pw" value="${credential.vm_user_password}" readonly></div>
                                   <div  class="vm-infobox-content-login-info-data ${bgColor}">${credential.domain_name}</div>
                                   <div  class="vm-infobox-content-login-info-login ${bgColor}">${formattedLogin}</div>
                `;
                parent_div.appendChild(iDiv);
        });
    } catch (error) {
        console.error("Filter Error:", error);
    }
}

let searchTimeout = null;

document.getElementById('vmSearchInput').addEventListener('input', function () {
    clearTimeout(searchTimeout);
    const queryItem = this.value.trim();

    document.querySelector(".search_predictions").style.visibility="visible";

    if(queryItem.length == 0){
        console.log("YES: ",queryItem.length )
        document.querySelector(".search_predictions").style.visibility="hidden";
        PupulateUserVMAdministration(0, '', '');
    }


    searchTimeout = setTimeout(async () => {
        try {
                const res = await fetch(`/api/predictive-search?qItem=${encodeURIComponent(queryItem)}`);
                const data = await res.json();

                const results = data.search_results || [];
                const ul = document.getElementById('search_predictions');
                ul.innerHTML = '';

                if(results.length > 0){
                results.forEach((item, index) => {
                    const ilist = document.createElement('li');
                    ilist.innerHTML = `
                        <img class="magnifier_ico" src="/static/images/magnifier-ico.svg"><span>${item.proxmox_vm_name} </span>
                    `;
                    ilist.onclick = () =>{
                        PupulateUserVMAdministration(0, '', item.proxmox_vm_id);
                    }
                    ilist.addEventListener('click', () => {
                        document.getElementById('vmSearchInput').value = item.proxmox_vm_name;
                        ul.innerHTML = ''; //clear predicte search results 
                        const parent_div = document.getElementById("vm_search_dataset"); //cleanup infinte scroller
                        parent_div.innerHTML="";
                        document.querySelector(".search_predictions").style.visibility="hidden";
                    });
                    ul.appendChild(ilist);
                });
            }else{
                const ilist = document.createElement('li');
                ilist.innerHTML = `
                    <img class="magnifier_ico" src="/static/images/cross-ico.svg") }}"> ...no results returned.
                `;
                ul.appendChild(ilist);
            }
            } catch (e) {
                console.error("Search failed", e);
            }
        }, 300); // give it a time to breath in between key inputs/api calls


});
    
let isLoading = false;
let currentPage = 0;
const pageSize = 10;

async function PupulateUserVMAdministration(page, queryItem,vmid) {
    if (isLoading) return; // Prevent duplicate calls
    isLoading = true;

    if(page == null){
        page = currentPage ;
    }
    currentPage = page;


    if(!queryItem) {
       queryItem = ""; //do not set to null otherwise parameter getss changed to null as string on the api side.
    }
    if(!vmid){
        vmid = "";//do not set to null otherwise parameter getss changed to null as string on the api side.
    }

    try {
        const response = await fetch(`/api/get-vm-user-search-machines?page=${currentPage}&size=${pageSize}&qItem=${encodeURIComponent(queryItem)}&vmid=${vmid}`, {
            method: 'GET',
            credentials: 'include'
        });

        if (!response.ok) {
            throw new Error(`HTTP error! Status: ${response.status}`);
        }

        const data = await response.json();
        const vm_list = data["VMs_list"];

        if (data.success && vm_list.length > 0) {
            const parent_div = document.getElementById("vm_search_dataset");
            if(currentPage == 0  ) {
                parent_div.innerHTML="";
            }
            showPageIndicator(currentPage); // Show page number

            vm_list.forEach((vm, index) => {
                const iDiv = document.createElement('div');
                iDiv.className = 'vm-infobox-content-search-data';

                const logonstatus = vm.status === 'running' ? 'Connect to machine' : 'Unavailable for connection';
                const statusCSS = vm.status === 'running' ? 'vm-admin-search-results-ico-hover' : '';

                iDiv.innerHTML = `
                    <div class="vm-infobox-content-search-container-data">
                        <img class="vm-admin-search-results-ico ${statusCSS}" title="${logonstatus}" src="/static/${vm.logon_status_ico || 'images/logon_ico.png'}">
                    </div>
                    <div class="vm-infobox-content-search-info-data">
                        <div class="search-result-server">${vm.proxmox_vm_name}</div>
                        <div class="search-result-function">${vm.vm_function}</div>
                        <div class="search-result-status">${vm.status}</div>
                    </div>
                    <div class="vm-infobox-content-search-container-data">
                        <img class="vm-admin-search-OS-ico" src="/static/${vm.os_logo_img_path || 'images/os_default.png'}">
                    </div>
                    <div class="vm-infobox-content-search-container-data">
                        <img class="vm-admin-search-favorite-ico" src="/static/${vm.isFavorite}">
                    </div>
                    <div class="vm-infobox-content-search-container-data">
                        <img class="vm-admin-search-more-ico" src="/static/images/more_ico.png">
                    </div>
                `;

                parent_div.appendChild(iDiv);
            });

            currentPage++; // Only increment if data returned
        } else {
            console.log("No more data to load.");
        }
    } catch (error) {
        console.error("Fetch Error:", error);
    } finally {
        isLoading = false;
    }
}

// Attach infinite scroll listener
document.getElementById("vm_search_dataset").addEventListener("scroll", function () {
    const container = this;

    if (container.scrollTop + container.clientHeight >= container.scrollHeight - 10) {
        PupulateUserVMAdministration(currentPage, document.getElementById('vmSearchInput').value ,'');
    }
});

//Hide predictive seach on inpurbox focus out
document.addEventListener('click', (e) => {
    const predBox = document.querySelector('.search_predictions');
    if (!document.getElementById('vmSearchInput').contains(e.target)) {
        predBox.style.visibility = 'hidden';
    }
});

//On enter search for whatever search term on input
document.getElementById('vmSearchInput').addEventListener('keydown', function (e) {
    if (e.key === 'Enter') {
        const parent_div = document.getElementById("vm_search_dataset");
        parent_div.innerHTML="";
        PupulateUserVMAdministration(0, document.getElementById('vmSearchInput').value ,'');
        document.querySelector(".search_predictions").style.visibility="hidden";
    }
});

function showPageIndicator(page) {
    const indicator = document.getElementById('page-indicator');
    indicator.textContent = `Page ${page + 1}`; // Pages start at 0
    indicator.style.opacity = 1;

    clearTimeout(indicator._hideTimer);
    indicator._hideTimer = setTimeout(() => {
        indicator.style.opacity = 0;
    }, 1500);
}

//Initial call on load
PupulateUserVMAdministration();



