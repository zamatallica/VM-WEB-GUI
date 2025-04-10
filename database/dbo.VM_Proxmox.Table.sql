USE [webInterface]
GO
/****** Object:  Table [dbo].[VM_Proxmox]    Script Date: 3/25/2025 1:44:36 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[VM_Proxmox](
	[proxmox_id] [int] IDENTITY(1,1) NOT NULL,
	[proxmox_host_name] [varchar](255) NOT NULL,
	[proxmox_node_name] [varchar](255) NOT NULL,
	[proxmox_url] [varchar](255) NOT NULL,
	[proxmox_api_base] [varchar](255) NOT NULL,
	[proxmox_port] [int] NOT NULL,
PRIMARY KEY CLUSTERED 
(
	[proxmox_id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
