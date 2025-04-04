USE [webInterface]
GO
/****** Object:  StoredProcedure [dbo].[sp_AssignRoleToUser]    Script Date: 3/25/2025 1:44:36 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

-- ======================================================================================
-- Author:      Alejandro Escobedo
-- Create date: 3/13/2025
--    v1.0      3/13/2025 aescobedo Initial version.
-- Description: Assigns a role to a user by inserting a record into the users_roles table.
-- ======================================================================================
CREATE PROCEDURE [dbo].[sp_AssignRoleToUser]
    @UserId INT,
    @RoleId INT
AS
BEGIN
    SET NOCOUNT ON;

    -- Step 1: Validate UserId exists
    IF NOT EXISTS (SELECT 1 FROM dbo.users WHERE UserId = @UserId)
    BEGIN
        PRINT ' ERROR: User does not exist.';
        RETURN;
    END

    -- Step 2: Validate RoleId exists
    IF NOT EXISTS (SELECT 1 FROM dbo.roles WHERE role_id = @RoleId)
    BEGIN
        PRINT ' ERROR: Role does not exist.';
        RETURN;
    END

    -- Step 3: Check if the user already has the role assigned
    IF EXISTS (SELECT 1 FROM dbo.users_roles WHERE UserId = @UserId AND role_id = @RoleId)
    BEGIN
        PRINT ' INFO: User already has this role assigned.';
        RETURN;
    END

    -- Step 4: Assign the role
    BEGIN TRY
        INSERT INTO dbo.users_roles (UserId, role_id)
        VALUES (@UserId, @RoleId);

        PRINT ' SUCCESS: Role assigned to user successfully.';
    END TRY
    BEGIN CATCH
        PRINT ' ERROR: Failed to assign role. ' + ERROR_MESSAGE();
    END CATCH
END;
GO
