USE [webInterface]
GO
/****** Object:  StoredProcedure [dbo].[sp_generate_api_token]    Script Date: 3/25/2025 1:44:36 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- ============================================================================================================
-- Author:      Alejandro Escobedo
-- Create date: 3/10/2025
--    v1.0      3/10/2025 aescobedo Initial version.


-- Description: Generates an ProxMox API Token for use when CURLING PROXMOX for quering data or other auth related
--              interaction with PROXMOX via CURL.
-- =============================================================================================================
CREATE PROCEDURE [dbo].[sp_generate_api_token]
    @token_id INT,
    @pve_api_token NVARCHAR(255) OUTPUT
AS
BEGIN
    SET NOCOUNT ON;

    -- Ensure the token exists before generating the API token
    IF NOT EXISTS (SELECT 1 FROM dbo.proxmox_api_tokens WHERE token_id = @token_id)
    BEGIN
        PRINT 'ERROR: The provided token_id does not exist in proxmox_api_tokens.';
        RETURN;
    END

	-- Open the symmetric key for decryption
    OPEN SYMMETRIC KEY TokenEncKey
    DECRYPTION BY CERTIFICATE TokenEncryptionCert;

    -- Generate the API token dynamically
    SELECT 
        @pve_api_token = [user_name] + '!' + token_name + '=' +  CONVERT(NVARCHAR(255), DecryptByKey(secret))
    FROM 
        dbo.proxmox_api_tokens
    WHERE 
        token_id = @token_id;

	-- Close the symmetric key
    CLOSE SYMMETRIC KEY TokenEncKey;

    -- Return the generated API token
    SELECT @pve_api_token AS GeneratedAPIToken;
END;
GO
