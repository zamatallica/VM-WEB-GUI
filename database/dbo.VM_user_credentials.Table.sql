USE [webInterface]
GO
/****** Object:  Table [dbo].[VM_user_credentials]    Script Date: 3/25/2025 1:44:36 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[VM_user_credentials](
	[vm_credential_id] [int] IDENTITY(1,1) NOT NULL,
	[userid] [int] NOT NULL,
	[vm_id] [int] NULL,
	[os_id] [int] NOT NULL,
	[vm_username] [varchar](100) NOT NULL,
	[vm_user_password_hash] [varchar](512) NULL,
	[domain_id] [int] NOT NULL,
	[auth_method_id] [int] NOT NULL,
	[vm_last_logon] [datetime] NULL,
PRIMARY KEY CLUSTERED 
(
	[vm_credential_id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
ALTER TABLE [dbo].[VM_user_credentials]  WITH CHECK ADD FOREIGN KEY([auth_method_id])
REFERENCES [dbo].[authentication_method] ([auth_method_id])
GO
ALTER TABLE [dbo].[VM_user_credentials]  WITH CHECK ADD FOREIGN KEY([domain_id])
REFERENCES [dbo].[VM_logon_domains] ([domain_id])
GO
ALTER TABLE [dbo].[VM_user_credentials]  WITH CHECK ADD FOREIGN KEY([os_id])
REFERENCES [dbo].[OS_type] ([os_id])
GO
ALTER TABLE [dbo].[VM_user_credentials]  WITH CHECK ADD FOREIGN KEY([userid])
REFERENCES [dbo].[users] ([UserId])
GO
ALTER TABLE [dbo].[VM_user_credentials]  WITH CHECK ADD FOREIGN KEY([vm_id])
REFERENCES [dbo].[VMs] ([vm_id])
GO
