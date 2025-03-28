USE [webInterface]
GO
/****** Object:  StoredProcedure [dbo].[usp_GetUserVMs_backend]    Script Date: 3/25/2025 1:44:36 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

-- ======================================================================================
-- Author:      Alejandro Escobedo
-- Create date: 3/13/2025
--    v1.1      3/13/2025 aescobedo Updated to read from vw_UserVMs.
-- Description: Retrieves VMs assigned to a specific user based on role-based permissions.
--				for use with the backend
-- ======================================================================================
CREATE PROCEDURE [dbo].[usp_GetUserVMs_backend]
    @userid NVARCHAR(255)
AS
BEGIN
    SET NOCOUNT ON;

    -- Retrieve user VMs from the view
    SELECT 
        uvm.proxmox_vm_id,
        uvm.proxmox_vm_name
    FROM vw_UserVMs uvm
    WHERE uvm.userId = @userid
    ORDER BY uvm.vm_type_id;
END;

GO
