USE [webInterface]
GO
/****** Object:  StoredProcedure [dbo].[sp_Create_Permission]    Script Date: 3/25/2025 1:44:36 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- ============================================================================================================
-- Author:      Alejandro Escobedo
-- Create date: 3/10/2025
--    v1.0      3/10/2025 aescobedo Initial version.


-- Description: Create a new permission for Web Gui administration of PROXMOX.
-- =============================================================================================================
	CREATE PROCEDURE [dbo].[sp_Create_Permission]
    @PermissionName NVARCHAR(255),
    @Description NVARCHAR(255)
AS
BEGIN
    SET NOCOUNT ON;

    -- Check if the permission already exists
    IF EXISTS (SELECT 1 FROM permissions WHERE permission_name = @PermissionName)
    BEGIN
        PRINT 'Error: Permission already exists!';
        RETURN;
    END

    -- Insert new permission
    INSERT INTO permissions (permission_name, description, created_at, updated_at)
    VALUES (@PermissionName, @Description, GETDATE(), GETDATE());

    PRINT 'Success: Permission created!';
END;
GO
