USE [webInterface]
GO
/****** Object:  StoredProcedure [dbo].[usp_AddProxmoxAPIToken]    Script Date: 3/25/2025 1:44:36 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- ============================================================================================================
-- Author:      Alejandro Escobedo
-- Create date: 3/10/2025
--    v1.0      3/10/2025 aescobedo Initial version.


-- Description: Add a new API token.
-- =============================================================================================================
CREATE PROCEDURE [dbo].[usp_AddProxmoxAPIToken]
    @proxmox_id INT,
    @user_name VARCHAR(25),
    @token_name VARCHAR(25),
    @secret VARCHAR(255)
AS
BEGIN
    SET NOCOUNT ON;

    -- Step 1: Ensure the provided proxmox_id exists in VM_Proxmox
    IF NOT EXISTS (SELECT 1 FROM dbo.VM_Proxmox WHERE proxmox_id = @proxmox_id)
    BEGIN
        PRINT 'ERROR: The provided proxmox_id does not exist in VM_Proxmox.';
        RETURN;
    END

    -- Open the symmetric key for encryption
    OPEN SYMMETRIC KEY TokenEncKey
    DECRYPTION BY CERTIFICATE TokenEncryptionCert;

    -- Insert the encrypted API token
    INSERT INTO dbo.proxmox_api_tokens (proxmox_id, user_name, token_name, secret)
    VALUES (
        @proxmox_id,
        @user_name,
        @token_name,
        EncryptByKey(Key_GUID('TokenEncKey'), @secret)
    );

    -- Close the symmetric key
    CLOSE SYMMETRIC KEY TokenEncKey;

    PRINT 'API token successfully added.';
END;
GO
