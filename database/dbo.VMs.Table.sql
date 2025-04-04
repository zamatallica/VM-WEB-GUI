USE [webInterface]
GO
/****** Object:  Table [dbo].[VMs]    Script Date: 3/25/2025 1:44:36 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[VMs](
	[vm_id] [int] IDENTITY(1,1) NOT NULL,
	[proxmox_vm_id] [tinyint] NOT NULL,
	[proxmox_vm_name] [varchar](255) NOT NULL,
	[proxmox_id] [int] NOT NULL,
	[vm_type_id] [int] NOT NULL,
PRIMARY KEY CLUSTERED 
(
	[vm_id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
ALTER TABLE [dbo].[VMs]  WITH CHECK ADD  CONSTRAINT [FK_VMs_VM_Proxmox] FOREIGN KEY([proxmox_id])
REFERENCES [dbo].[VM_Proxmox] ([proxmox_id])
GO
ALTER TABLE [dbo].[VMs] CHECK CONSTRAINT [FK_VMs_VM_Proxmox]
GO
ALTER TABLE [dbo].[VMs]  WITH CHECK ADD  CONSTRAINT [FK_VMs_vm_types] FOREIGN KEY([vm_type_id])
REFERENCES [dbo].[vm_types] ([vm_type_id])
GO
ALTER TABLE [dbo].[VMs] CHECK CONSTRAINT [FK_VMs_vm_types]
GO
