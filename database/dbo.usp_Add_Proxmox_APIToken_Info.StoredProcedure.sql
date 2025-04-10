USE [webInterface]
GO
/****** Object:  StoredProcedure [dbo].[usp_Add_Proxmox_APIToken_Info]    Script Date: 3/25/2025 1:44:36 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- ============================================================================================================
-- Author:      Alejandro Escobedo
-- Create date: 3/10/2025
--    v1.0      3/10/2025 aescobedo Initial version.


-- Description: Adds Descrition for API Tokens and their intended usage.
-- =============================================================================================================
CREATE PROCEDURE [dbo].[usp_Add_Proxmox_APIToken_Info]
    @token_id INT,
    @status VARCHAR(20) = 'active', -- Default status is 'active'
    @description NVARCHAR(255) = NULL  -- Optional description
AS
BEGIN
    SET NOCOUNT ON;

    -- Step 1: Ensure the provided token_id exists in proxmox_api_tokens
    IF NOT EXISTS (SELECT 1 FROM dbo.proxmox_api_tokens WHERE token_id = @token_id)
    BEGIN
        PRINT 'ERROR: The provided token_id does not exist in proxmox_api_tokens.';
        RETURN;
    END

    -- Step 2: Insert the token info
    INSERT INTO dbo.proxmox_api_tokens_info (token_id, status, description)
    VALUES (@token_id, @status, @description);

    PRINT 'Token info successfully added.';
END;
GO
