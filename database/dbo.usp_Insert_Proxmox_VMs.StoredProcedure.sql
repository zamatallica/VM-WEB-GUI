USE [webInterface]
GO
/****** Object:  StoredProcedure [dbo].[usp_Insert_Proxmox_VMs]    Script Date: 3/25/2025 1:44:36 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- ============================================================================================================
-- Author:      Alejandro Escobedo
-- Create date: 3/10/2025
--    v1.0      3/10/2025 aescobedo Initial version.


-- Description: CURLs into PROXMOX to rewtrieve the VM's for a particular Node, it needs API token to authenticate
--              secret needs to be decrypted previously using [dbo].[usp_Get_Decrypted_Proxmox_APIToken].
--				API Token is genertated using sp_generate_api_token (already provides decrypted secret)	
-- =============================================================================================================
CREATE PROCEDURE [dbo].[usp_Insert_Proxmox_VMs]
    @proxmox_id INT,          -- Proxmox ID from VM_Proxmox table
    @pve_api_token NVARCHAR(500) -- Proxmox API Token
AS
BEGIN
    SET NOCOUNT ON;

    -- Step 1: Ensure the VM_Info table exists
    IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'VM_Info')
    BEGIN
        CREATE TABLE VM_Info (
            proxmox_vm_id INT PRIMARY KEY,
            proxmox_id INT,
            Name NVARCHAR(255),
            Status NVARCHAR(50),
            MaxMem BIGINT,
            MaxCPU INT,
            Uptime BIGINT
        );
    END
    ELSE
        TRUNCATE TABLE VM_Info;  -- Truncate only once

    -- Step 2: Retrieve Proxmox URL from VM_Proxmox table
    DECLARE @proxmox_url NVARCHAR(500);
    SELECT @proxmox_url = proxmox_url 
    FROM dbo.VM_Proxmox
    WHERE proxmox_id = @proxmox_id;

    -- Ensure URL is not NULL
    IF @proxmox_url IS NULL
    BEGIN
        PRINT 'ERROR: No Proxmox URL found for the given proxmox_id';
        RETURN;
    END

    -- Step 3: Create a temporary table to store JSON response
    CREATE TABLE #CurlOutput (Response NVARCHAR(MAX));

    -- Step 4: Construct and execute curl command
    DECLARE @curl_cmd NVARCHAR(MAX), @curl_cmd_VC VARCHAR(8000);

    SET @curl_cmd = 
        'curl -k -s --header "Authorization: PVEAPIToken=' 
        + @pve_api_token + '" "' 
        + @proxmox_url + '/api2/json/cluster/resources?type=vm"';

    -- Debugging: Print the constructed curl command
    PRINT 'Executing CURL: ' + @curl_cmd;

    -- Convert to VARCHAR(8000) before executing xp_cmdshell
    SET @curl_cmd_VC = CAST(@curl_cmd AS VARCHAR(8000));

    INSERT INTO #CurlOutput (Response)
    EXEC xp_cmdshell @curl_cmd_VC;

    -- Step 5: Extract and clean JSON response
    DECLARE @json NVARCHAR(MAX);

    SELECT @json = STRING_AGG(Response, '')
    FROM #CurlOutput
    WHERE Response IS NOT NULL AND Response NOT LIKE '%NULL%';

    -- Debugging: Print the JSON output
    PRINT 'JSON Response: ' + ISNULL(@json, 'NULL');

    -- Step 6: Validate JSON format before inserting data
    IF @json IS NULL OR LEN(@json) = 0
    BEGIN
        PRINT 'ERROR: No JSON response received';
        DROP TABLE #CurlOutput;
        RETURN;
    END

    IF ISJSON(@json) = 1  
    BEGIN
        -- Insert parsed JSON data into VM_Info table
        INSERT INTO VM_Info (proxmox_vm_id, proxmox_id, Name, Status, MaxMem, MaxCPU, Uptime)
        SELECT
            vmid,            -- proxmox_vm_id from JSON
            @proxmox_id,     -- Insert provided proxmox_id explicitly
            Name,
            Status,
            MaxMem,
            MaxCPU,
            Uptime
        FROM OPENJSON(@json, '$.data')
        WITH (
            vmid INT '$.vmid',
            Name NVARCHAR(255) '$.name',
            Status NVARCHAR(50) '$.status',
            MaxMem BIGINT '$.maxmem',
            MaxCPU INT '$.maxcpu',
            Uptime BIGINT '$.uptime'
        );

        PRINT 'Data inserted successfully.';
    END
    ELSE
    BEGIN
        PRINT 'ERROR: Invalid JSON format received';
    END

    -- Step 7: Drop the temporary table
    DROP TABLE #CurlOutput;
END;
GO
