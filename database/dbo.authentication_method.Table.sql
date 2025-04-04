USE [webInterface]
GO
/****** Object:  Table [dbo].[authentication_method]    Script Date: 3/25/2025 1:44:36 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[authentication_method](
	[auth_method_id] [int] NOT NULL,
	[auth_method_name] [varchar](50) NOT NULL,
PRIMARY KEY CLUSTERED 
(
	[auth_method_id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
