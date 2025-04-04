USE [webInterface]
GO
/****** Object:  Table [dbo].[proxmox_api_tokens]    Script Date: 3/25/2025 1:44:36 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[proxmox_api_tokens](
	[token_id] [int] IDENTITY(1,1) NOT NULL,
	[proxmox_id] [int] NOT NULL,
	[user_name] [varchar](25) NOT NULL,
	[token_name] [varchar](25) NOT NULL,
	[secret] [varchar](255) NULL,
 CONSTRAINT [PK_proxmox_api_tokens] PRIMARY KEY CLUSTERED 
(
	[token_id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
ALTER TABLE [dbo].[proxmox_api_tokens]  WITH CHECK ADD  CONSTRAINT [FK_proxmox_api_tokens_proxmox] FOREIGN KEY([proxmox_id])
REFERENCES [dbo].[VM_Proxmox] ([proxmox_id])
ON UPDATE CASCADE
ON DELETE CASCADE
GO
ALTER TABLE [dbo].[proxmox_api_tokens] CHECK CONSTRAINT [FK_proxmox_api_tokens_proxmox]
GO
