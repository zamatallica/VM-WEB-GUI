USE [webInterface]
GO
/****** Object:  StoredProcedure [dbo].[usp_get_user_vm_credentials]    Script Date: 3/25/2025 1:44:36 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

-- ======================================================================================
-- Author:      Alejandro Escobedo
-- Create date: 3/13/2025
--    v1.0      3/25/2025 aescobedo Initial version.
-- Description: Retrieves user  credentials for the VM local and domain.
-- ======================================================================================

CREATE PROCEDURE [dbo].[usp_get_user_vm_credentials]
       @UserId INT
	 , @ProxmoxVMId INT
AS
BEGIN
    SET NOCOUNT ON;

WITH FilteredCreds AS (
		SELECT * 
		FROM vw_vm_User_Credentials
		WHERE 
			UserId = @UserId
			AND (
				proxmox_vm_id = @ProxmoxVMId
				OR proxmox_vm_id IS NULL
				)
		)

SELECT 
	  fc.account_username
	, fc.credential_username
	, fc.vm_user_password_hash
	, fc.domain_name
	, fc.auth_method_name
	, fc.vm_last_logon
FROM FilteredCreds fc
INNER JOIN 
	vw_UserVMs uvm
    ON
		fc.UserId        = uvm.UserId
   AND uvm.proxmox_vm_id = @ProxmoxVMId;
END;
GO
