USE [webInterface]
GO
/****** Object:  StoredProcedure [dbo].[usp_Get_Decrypted_Proxmox_APIToken]    Script Date: 3/25/2025 1:44:36 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- ============================================================================================================
-- Author:      Alejandro Escobedo
-- Create date: 3/10/2025
--    v1.0      3/10/2025 aescobedo Initial version.


-- Description: Gets API Token and decrypts its Secret key.
-- =============================================================================================================
CREATE PROCEDURE [dbo].[usp_Get_Decrypted_Proxmox_APIToken]
    @token_id INT
AS
BEGIN
    SET NOCOUNT ON;

    -- Ensure the token exists before decrypting
    IF NOT EXISTS (SELECT 1 FROM dbo.proxmox_api_tokens WHERE token_id = @token_id)
    BEGIN
        PRINT 'ERROR: The provided token_id does not exist in proxmox_api_tokens.';
        RETURN;
    END

    -- Open the symmetric key for decryption
    OPEN SYMMETRIC KEY TokenEncKey
    DECRYPTION BY CERTIFICATE TokenEncryptionCert;

    -- Retrieve and decrypt the API token
    SELECT 
        proxmox_id, 
        user_name, 
        token_name, 
        CONVERT(NVARCHAR(255), DecryptByKey(secret)) AS decrypted_secret
    FROM dbo.proxmox_api_tokens
    WHERE token_id = @token_id;

    -- Close the symmetric key
    CLOSE SYMMETRIC KEY TokenEncKey;
END;
GO
