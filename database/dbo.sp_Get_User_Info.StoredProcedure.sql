USE [webInterface]
GO
/****** Object:  StoredProcedure [dbo].[sp_Get_User_Info]    Script Date: 3/15/2025 12:10:07 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- ============================================================================================================
-- Author:      Alejandro Escobedo
-- Create date: 3/10/2025
--    v1.0      3/10/2025 aescobedo Initial version.


-- Description: Retrieves user's extnded info for WEB GUI profile.
-- =============================================================================================================
CREATE PROCEDURE [dbo].[sp_Get_User_Info]
    @UserId INT
AS
BEGIN
    SET NOCOUNT ON;

    SELECT 
			first_name, 
			last_name, 
			email, 
			profile_pic,
			first_name + ' ' + SUBSTRING(last_name,1,1)+ '.'  as 'alias'
    FROM 
		user_info
    WHERE
		UserId = @UserId;
END;
GO
