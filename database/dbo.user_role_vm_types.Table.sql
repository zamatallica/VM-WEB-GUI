USE [webInterface]
GO
/****** Object:  Table [dbo].[user_role_vm_types]    Script Date: 3/25/2025 1:44:36 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[user_role_vm_types](
	[role_id] [int] NOT NULL,
	[vm_type_id] [int] NOT NULL,
PRIMARY KEY CLUSTERED 
(
	[role_id] ASC,
	[vm_type_id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
ALTER TABLE [dbo].[user_role_vm_types]  WITH CHECK ADD  CONSTRAINT [FK_user_role_vm_types_roles] FOREIGN KEY([role_id])
REFERENCES [dbo].[roles] ([role_id])
ON UPDATE CASCADE
ON DELETE CASCADE
GO
ALTER TABLE [dbo].[user_role_vm_types] CHECK CONSTRAINT [FK_user_role_vm_types_roles]
GO
ALTER TABLE [dbo].[user_role_vm_types]  WITH CHECK ADD  CONSTRAINT [FK_user_role_vm_types_vm_types] FOREIGN KEY([vm_type_id])
REFERENCES [dbo].[vm_types] ([vm_type_id])
ON UPDATE CASCADE
ON DELETE CASCADE
GO
ALTER TABLE [dbo].[user_role_vm_types] CHECK CONSTRAINT [FK_user_role_vm_types_vm_types]
GO
