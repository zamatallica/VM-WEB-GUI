USE [webInterface]
GO
/****** Object:  StoredProcedure [dbo].[sp_AssignPermissionToRole]    Script Date: 3/25/2025 1:44:36 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- ======================================================================================
-- Author:      Alejandro Escobedo
-- Create date: 3/13/2025
--    v1.0      3/13/2025 aescobedo Initial version.
-- Description: Assigns a permission to a role by inserting a record into the permissions_role table.
-- ======================================================================================
CREATE PROCEDURE [dbo].[sp_AssignPermissionToRole]
    @PermissionId INT,
    @RoleId INT
AS
BEGIN
    SET NOCOUNT ON;

    -- Step 1: Validate PermissionId exists
    IF NOT EXISTS (SELECT 1 FROM dbo.permissions WHERE permissions_id = @PermissionId)
    BEGIN
        PRINT ' ERROR: Permission does not exist.';
        RETURN;
    END

    -- Step 2: Validate RoleId exists
    IF NOT EXISTS (SELECT 1 FROM dbo.roles WHERE role_id = @RoleId)
    BEGIN
        PRINT ' ERROR: Role does not exist.';
        RETURN;
    END

    -- Step 3: Check if the permission is already assigned to the role
    IF EXISTS (SELECT 1 FROM dbo.permissions_role WHERE permissions_id = @PermissionId AND role_id = @RoleId)
    BEGIN
        PRINT ' INFO: Permission is already assigned to this role.';
        RETURN;
    END

    -- Step 4: Assign the permission to the role
    BEGIN TRY
        INSERT INTO dbo.permissions_role (permissions_id, role_id)
        VALUES (@PermissionId, @RoleId);

        PRINT ' SUCCESS: Permission assigned to role successfully.';
    END TRY
    BEGIN CATCH
        PRINT ' ERROR: Failed to assign permission. ' + ERROR_MESSAGE();
    END CATCH
END;
GO
