USE [webInterface]
GO
/****** Object:  StoredProcedure [dbo].[sp_add_user]    Script Date: 3/25/2025 1:44:36 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- ============================================================================================================
-- Author:      Alejandro Escobedo
-- Create date: 3/10/2025
--    v1.0      3/10/2025 aescobedo Initial version.


-- Description: Adds new user for WEB GUI.
-- =============================================================================================================
CREATE PROCEDURE [dbo].[sp_add_user]
    @Username  NVARCHAR(50),
    @FirstName NVARCHAR(50),
    @LastName NVARCHAR(255),
    @Email NVARCHAR(255),
    @Password NVARCHAR(255),  -- Password is expected to be already hashed
    @ProfilePic NVARCHAR(255) = NULL
AS
BEGIN
    SET NOCOUNT ON;

    DECLARE @NewUserId INT;
    DECLARE @CurrentDate DATETIME = GETDATE();

    -- Insert into users table
    INSERT INTO users (Username, PasswordHash, status_id, created_at, updated_at)
    VALUES (@Username, @Password, 1, @CurrentDate, @CurrentDate);

    -- Get the newly created User ID
    SET @NewUserId = SCOPE_IDENTITY();

    -- Insert user details into user_info table
    INSERT INTO user_info (UserId, first_name, last_name, email, profile_pic)
    VALUES (@NewUserId, @FirstName, @LastName, @Email, @ProfilePic);

	-- Insert user details into users_password table
	INSERT INTO [dbo].[users_password] (UserId,failed_attempts, last_attempt, last_changed)
	VALUES (@NewUserId,0,NULL,GETDATE())


    -- Return the new user ID
    SELECT @NewUserId AS NewUserID;
END;
GO
