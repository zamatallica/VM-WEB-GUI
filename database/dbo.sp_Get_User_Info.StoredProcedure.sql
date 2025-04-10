USE [webInterface]
GO
/****** Object:  StoredProcedure [dbo].[sp_Get_User_Info]    Script Date: 3/25/2025 1:44:36 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- ============================================================================================================
-- Author:      Alejandro Escobedo
-- Create date: 3/10/2025
--    v1.0      3/10/2025 aescobedo Initial version.
--    v1.1      3/22/2025 aescobedo Included User's role.

-- Description: Retrieves user's extnded info for WEB GUI profile.
-- =============================================================================================================
CREATE PROCEDURE [dbo].[sp_Get_User_Info]
    @UserId INT
AS
BEGIN
    SET NOCOUNT ON;

    SELECT 
			ui.first_name, 
			ui.last_name, 
			ui.email, 
			ui.profile_pic,
			ui.first_name + ' ' + SUBSTRING(last_name,1,1)+ '.'  as 'alias',
			r.role_name
    FROM 
		user_info ui
		inner join users_roles ur
		on ui.UserId = ur.UserId
		INNER JOIN  roles r
		on r.role_id = ur.role_id
    WHERE
		ui.UserId = @UserId;
END;
GO
