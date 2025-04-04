USE [webInterface]
GO
/****** Object:  StoredProcedure [dbo].[sp_GetUserForLogin]    Script Date: 3/25/2025 1:44:36 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- ============================================================================================================
-- Author:      Alejandro Escobedo
-- Create date: 3/10/2025
--    v1.0      3/10/2025 aescobedo Initial version.


-- Description: Used in WEB GUI for API LOGIN.
-- =============================================================================================================
CREATE PROCEDURE [dbo].[sp_GetUserForLogin] 
    @username NVARCHAR(255)
AS
BEGIN
    SET NOCOUNT ON;

    SELECT 
        u.UserId, 
        u.PasswordHash, 
        COALESCE(up.failed_attempts, 0) AS failed_attempts, 
        up.last_attempt
    FROM users u
    LEFT JOIN users_password up ON u.UserId = up.UserId
    WHERE u.username = @username;
END;
GO
