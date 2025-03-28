USE [webInterface]
GO
/****** Object:  StoredProcedure [dbo].[sp_Create_VMType]    Script Date: 3/25/2025 1:44:36 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- ============================================================================================================
-- Author:      Alejandro Escobedo
-- Create date: 3/10/2025
--    v1.0      3/10/2025 aescobedo Initial version.


-- Description: Create a new VM Type.
-- =============================================================================================================
CREATE PROCEDURE [dbo].[sp_Create_VMType]
    @TypeName NVARCHAR(255)
	,@Description NVARCHAR(255)
AS
BEGIN
    SET NOCOUNT ON;

    -- Check if the VM type already exists
    IF EXISTS (SELECT 1 FROM dbo.vm_types WHERE [function] = @TypeName)
    BEGIN
        PRINT 'Error: VM Type already exists!';
        RETURN;
    END

    -- Insert new VM type
    INSERT INTO dbo.vm_types ([function], [description])
    VALUES (@TypeName, @Description);

    PRINT 'Success: VM Type created!';
END;

GO
