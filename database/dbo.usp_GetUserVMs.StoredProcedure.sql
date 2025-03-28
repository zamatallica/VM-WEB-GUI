USE [webInterface]
GO
/****** Object:  StoredProcedure [dbo].[usp_GetUserVMs]    Script Date: 3/25/2025 1:44:36 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

-- ======================================================================================
-- Author:      Alejandro Escobedo
-- Create date: 3/13/2025
--    v1.0      3/13/2025 aescobedo Initial version.
-- Description: Retrieves all VMs assigned to a user based on their role and VM type permissions.
-- ======================================================================================
CREATE PROCEDURE [dbo].[usp_GetUserVMs]
    @Username NVARCHAR(255)
AS
BEGIN
    SET NOCOUNT ON;

    DECLARE @UserID INT;

    -- Retrieve UserID for the given username
    SELECT @UserID = UserId FROM dbo.users WHERE Username = @Username;

    -- Ensure user exists
    IF @UserID IS NULL
    BEGIN
        PRINT 'Error: User not found.';
        RETURN;
    END

    -- Retrieve user's accessible VMs
    SELECT 
        u.UserId, 
        u.Username, 
        v.vm_id, 
        v.proxmox_vm_id,
        v.proxmox_vm_name, 
        v.proxmox_id
    FROM dbo.VMs v
    INNER JOIN user_role_vm_types urvt ON v.vm_type_id = urvt.vm_type_id
    LEFT JOIN users_roles ur ON ur.role_id = urvt.role_id
    INNER JOIN users u ON u.UserId = ur.UserId
    WHERE u.UserId = @UserID
    ORDER BY v.vm_type_id;
END;
GO
