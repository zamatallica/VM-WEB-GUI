
/* =====================================================================================
   File: init.js
   Author: Alejandro Escobedo
   Verion: 
                3/22/2025 Initial Created module js for init routines.
   -------------------------------------------------------------------
   Page initialization logic and preload routines.
   This file is responsible for:
   - Checking user session on page load
   - Fetching user profile information
   - Populating VM dropdown menu
   - Auto-starting refresh intervals for selected VM
   Should be loaded near the end of <body> to ensure DOM elements exist.
====================================================================================== */

async function getUserProfileInfo() {
    try{
        const response= await fetch('/api/user-info',{
            method: 'GET',
            credentials: 'include'
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
    }

    const data = await response.json();
    console.log("Fetching Users Pofile:", data);

    // Ensure the data exists before using it
    if (data.success) {
        const firstName   = data.first_name  || "Unknown";
        const lastName    = data.last_name   || "";
        const email       = data.email       || "No email";
        const profilePic  = data.profile_pic || "/static/images/user.png"; // Default pic if none
        const alias       = data.alias       || "Unknown";
        //full profile pic path
        const profilePicPath = `/static/images/${profilePic}`;
        const role        = data.role        || "User";
        console.log("Profile Pic Path:", profilePicPath);

    // Update UI elements
    //document.getElementById('username-display').textContent = `${firstName} ${lastName}`;
    //document.getElementById('user-email').textContent = email;
    document.getElementById('username-display').textContent    = alias;
    document.getElementById('profile-pic').src                 = profilePicPath;
    document.getElementById('vm-infobox-user-profile-pic').src = profilePicPath;
    document.getElementById('vm-infobox-content-user-text-name').textContent   = `${firstName} ${lastName}`;
    document.getElementById('vm-infobox-content-user-text-role').textContent   = `${role} role`
    } else {
        console.error("User profile retrieval failed:", data.message);
    }

    return data; // In case I use it elsewhere

} catch (error) {
        console.error("Unable to retrieve user's profile", error);
}
}

    async function populateVMsDropDown() {
    try {
        const response = await fetch('/api/get-vms', { 
            method: 'GET',
            credentials: 'include'
        });

        const data = await response.json();  

        if (data.success) {
            const select = document.getElementById("vmSelect");

            select.innerHTML = '<option value="">-- Choose a VM --</option>';

            data.vms.forEach(vm => {
                let option = document.createElement("option");
                option.value = vm.proxmox_vm_id;
                option.textContent = vm.proxmox_vm_name;
                select.appendChild(option);
            });

        } else {
            console.error("Error:", data.message);
        }
    } catch (error) {
        console.error("Fetch Error:", error);
    }
    }

    window.addEventListener('DOMContentLoaded', () => {
        populateVMsDropDown();
        getUserProfileInfo();
    });