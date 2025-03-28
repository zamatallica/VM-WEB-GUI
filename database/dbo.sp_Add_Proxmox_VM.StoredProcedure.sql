USE [webInterface]
GO
/****** Object:  StoredProcedure [dbo].[sp_Add_Proxmox_VM]    Script Date: 3/25/2025 1:44:36 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- ============================================================================================================
-- Author:      Alejandro Escobedo
-- Create date: 3/10/2025
--    v1.0      3/10/2025 aescobedo Initial version.


-- Description: Adds a ProxMox Host, note this is a ProxMox host no just a single VM.
-- =============================================================================================================
CREATE PROCEDURE [dbo].[sp_Add_Proxmox_VM]
    @proxmox_host_name VARCHAR(255),
    @proxmox_node_name VARCHAR(255),
    @proxmox_url VARCHAR(255),
    @proxmox_api_base VARCHAR(255),
    @proxmox_port INT
AS
BEGIN
    SET NOCOUNT ON;

    INSERT INTO dbo.VM_Proxmox (proxmox_host_name, proxmox_node_name, proxmox_url, proxmox_api_base, proxmox_port)
    VALUES (@proxmox_host_name, @proxmox_node_name, @proxmox_url, @proxmox_api_base, @proxmox_port);

    -- Return the newly created Proxmox ID
    SELECT SCOPE_IDENTITY() AS proxmox_id;
END;
GO
