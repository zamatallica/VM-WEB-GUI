USE [webInterface]
GO
/****** Object:  StoredProcedure [dbo].[sp_Create_Role]    Script Date: 3/25/2025 1:44:36 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- ============================================================================================================
-- Author:      Alejandro Escobedo
-- Create date: 3/10/2025
--    v1.0      3/10/2025 aescobedo Initial version.


-- Description: Create a new role for Web Gui administration of PROXMOX.
-- =============================================================================================================
CREATE PROCEDURE [dbo].[sp_Create_Role]
    @RoleName NVARCHAR(255),
    @Description NVARCHAR(255)
AS
BEGIN
    SET NOCOUNT ON;

    -- Check if the role already exists
    IF EXISTS (SELECT 1 FROM roles WHERE role_name = @RoleName)
    BEGIN
        PRINT 'Error: Role already exists!';
        RETURN;
    END

    -- Insert new role
    INSERT INTO roles (role_name, description, created_at, updated_at)
    VALUES (@RoleName, @Description, GETDATE(), GETDATE());

    PRINT 'Success: Role created!';
END;
GO
