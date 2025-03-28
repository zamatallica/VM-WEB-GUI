USE [webInterface]
GO
/****** Object:  StoredProcedure [dbo].[sp_ResetFailedAttempts]    Script Date: 3/25/2025 1:44:36 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- ============================================================================================================
-- Author:      Alejandro Escobedo
-- Create date: 3/10/2025
--    v1.0      3/10/2025 aescobedo Initial version.


-- Description: Handles WEB GUI's API auth attempts.
-- =============================================================================================================
CREATE PROCEDURE [dbo].[sp_ResetFailedAttempts]
    @UserId INT,
    @logon_status BIT  -- 0 = Successful login, 1 = Failed login attempt
AS
BEGIN
    SET NOCOUNT ON;

	IF NOT EXISTS(SELECT UserId FROM [dbo].[users_password] WHERE UserId = @UserId)
	BEGIN
		INSERT INTO [dbo].[users_password] (UserId,failed_attempts, last_attempt, last_changed)
		VALUES (@UserId,0,GETDATE(),GETDATE())
	END

    IF @logon_status = 0  -- Successful login: Reset failed attempts
    BEGIN
        UPDATE users_password
        SET failed_attempts = 0, last_attempt = GETDATE()
        WHERE UserId = @UserId;
    END
    ELSE 
	BEGIN-- Failed login attempt: Increment failed attempts
		UPDATE users_password
		SET failed_attempts = failed_attempts + 1, last_attempt = GETDATE()
		WHERE UserId = @UserId;
    END
END;
GO
