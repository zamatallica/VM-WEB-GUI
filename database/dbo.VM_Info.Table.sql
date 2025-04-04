USE [webInterface]
GO
/****** Object:  Table [dbo].[VM_Info]    Script Date: 3/25/2025 1:44:36 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[VM_Info](
	[proxmox_vm_id] [int] NOT NULL,
	[proxmox_id] [int] NULL,
	[Name] [nvarchar](255) NULL,
	[Status] [nvarchar](50) NULL,
	[MaxMem] [bigint] NULL,
	[MaxCPU] [int] NULL,
	[Uptime] [bigint] NULL,
PRIMARY KEY CLUSTERED 
(
	[proxmox_vm_id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
