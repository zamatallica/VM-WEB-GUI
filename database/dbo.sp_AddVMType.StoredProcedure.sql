USE [webInterface]
GO
/****** Object:  StoredProcedure [dbo].[sp_AddVMType]    Script Date: 3/15/2025 12:10:07 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- ============================================================================================================
-- Author:      Alejandro Escobedo
-- Create date: 3/10/2025
--    v1.0      3/10/2025 aescobedo Initial version.


-- Description: Adds a new VM type.
-- =============================================================================================================
CREATE PROCEDURE [dbo].[sp_AddVMType]
    @function VARCHAR(25),
    @description VARCHAR(255) = NULL
AS
BEGIN
    SET NOCOUNT ON;

    INSERT INTO dbo.vm_types ([function], [description])
    VALUES (@function, @description);

    -- Return the newly created VM Type ID
    SELECT SCOPE_IDENTITY() AS vm_type_id;
END;
GO
