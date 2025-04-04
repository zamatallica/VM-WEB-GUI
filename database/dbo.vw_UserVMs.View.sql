USE [webInterface]
GO
/****** Object:  View [dbo].[vw_UserVMs]    Script Date: 3/25/2025 1:44:36 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- ======================================================================================
-- Author:      Alejandro Escobedo
-- Create date: 3/13/2025
--    v1.0      3/13/2025 aescobedo Initial version.
-- Description: View to get all VMs assigned to users based on roles and VM type permissions.
-- ======================================================================================
CREATE VIEW [dbo].[vw_UserVMs] AS
SELECT 
    u.UserId, 
    u.Username, 
    v.vm_id, 
    v.proxmox_vm_id,
    v.proxmox_vm_name, 
    v.proxmox_id,
    v.vm_type_id,
    ur.role_id
FROM dbo.VMs v
INNER JOIN user_role_vm_types urvt ON v.vm_type_id = urvt.vm_type_id
LEFT JOIN users_roles ur ON ur.role_id = urvt.role_id
INNER JOIN users u ON u.UserId = ur.UserId
GO
