USE [webInterface]
GO
/****** Object:  User [webGui]    Script Date: 3/12/2025 12:50:29 AM ******/
CREATE USER [webGui] FOR LOGIN [webGui] WITH DEFAULT_SCHEMA=[dbo]
GO
ALTER ROLE [db_exec] ADD MEMBER [webGui]
GO
ALTER ROLE [db_datareader] ADD MEMBER [webGui]
GO
ALTER ROLE [db_datawriter] ADD MEMBER [webGui]
GO
