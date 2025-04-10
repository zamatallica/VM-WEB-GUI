USE [webInterface]
GO
/****** Object:  StoredProcedure [dbo].[usp_Update_Proxmox_APIToken_Encrypted]    Script Date: 3/25/2025 1:44:36 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- ============================================================================================================
-- Author:      Alejandro Escobedo
-- Create date: 3/10/2025
--    v1.0      3/10/2025 aescobedo Initial version.


-- Description: Encrypts API Secret if not previously encrypted. BETTER SAFE THAN SORRY.
-- =============================================================================================================
CREATE PROCEDURE [dbo].[usp_Update_Proxmox_APIToken_Encrypted]
    @token_id INT,
    @new_secret NVARCHAR(255)
AS
BEGIN
    SET NOCOUNT ON;

    -- Ensure the token exists
    IF NOT EXISTS (SELECT 1 FROM dbo.proxmox_api_tokens WHERE token_id = @token_id)
    BEGIN
        PRINT 'ERROR: The provided token_id does not exist in proxmox_api_tokens.';
        RETURN;
    END

    -- Open the symmetric key for encryption
    OPEN SYMMETRIC KEY TokenEncKey
    DECRYPTION BY CERTIFICATE TokenEncryptionCert;

    -- Update with encrypted token
    UPDATE dbo.proxmox_api_tokens
    SET secret = EncryptByKey(Key_GUID('TokenEncKey'), @new_secret)
    WHERE token_id = @token_id;

    -- Close the symmetric key
    CLOSE SYMMETRIC KEY TokenEncKey;

    PRINT 'API token successfully updated.';
END;
GO
