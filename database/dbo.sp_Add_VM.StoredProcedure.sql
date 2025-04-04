USE [webInterface]
GO
/****** Object:  StoredProcedure [dbo].[sp_Add_VM]    Script Date: 3/25/2025 1:44:36 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- ============================================================================================================
-- Author:      Alejandro Escobedo
-- Create date: 3/10/2025
--    v1.0      3/10/2025 aescobedo Initial version.


-- Description: Adds a new VM.
-- =============================================================================================================
CREATE PROCEDURE [dbo].[sp_Add_VM]
    @proxmox_vm_id TINYINT,
    @proxmox_vm_name VARCHAR(255),
    @proxmox_id INT,
    @vm_type_id INT
AS
BEGIN
    SET NOCOUNT ON;

    INSERT INTO dbo.VMs (proxmox_vm_id, proxmox_vm_name, proxmox_id, vm_type_id)
    VALUES (@proxmox_vm_id, @proxmox_vm_name, @proxmox_id, @vm_type_id);
END;
GO
