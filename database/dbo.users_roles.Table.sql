USE [webInterface]
GO
/****** Object:  Table [dbo].[users_roles]    Script Date: 3/25/2025 1:44:36 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[users_roles](
	[UserId] [int] NOT NULL,
	[role_id] [int] NOT NULL,
PRIMARY KEY CLUSTERED 
(
	[UserId] ASC,
	[role_id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
ALTER TABLE [dbo].[users_roles]  WITH NOCHECK ADD FOREIGN KEY([role_id])
REFERENCES [dbo].[roles] ([role_id])
ON DELETE CASCADE
GO
ALTER TABLE [dbo].[users_roles]  WITH NOCHECK ADD FOREIGN KEY([UserId])
REFERENCES [dbo].[users] ([UserId])
ON DELETE CASCADE
GO
