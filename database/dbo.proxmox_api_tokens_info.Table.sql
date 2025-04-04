USE [webInterface]
GO
/****** Object:  Table [dbo].[proxmox_api_tokens_info]    Script Date: 3/25/2025 1:44:36 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[proxmox_api_tokens_info](
	[token_id] [int] NOT NULL,
	[created_at] [datetime] NULL,
	[last_used_at] [datetime] NULL,
	[status] [varchar](20) NOT NULL,
	[description] [nvarchar](255) NULL,
 CONSTRAINT [PK_proxmox_api_tokens_info] PRIMARY KEY CLUSTERED 
(
	[token_id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY],
UNIQUE NONCLUSTERED 
(
	[token_id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
ALTER TABLE [dbo].[proxmox_api_tokens_info] ADD  DEFAULT (getdate()) FOR [created_at]
GO
ALTER TABLE [dbo].[proxmox_api_tokens_info] ADD  DEFAULT ('active') FOR [status]
GO
ALTER TABLE [dbo].[proxmox_api_tokens_info]  WITH CHECK ADD  CONSTRAINT [FK_proxmox_api_tokens_info] FOREIGN KEY([token_id])
REFERENCES [dbo].[proxmox_api_tokens] ([token_id])
ON UPDATE CASCADE
ON DELETE CASCADE
GO
ALTER TABLE [dbo].[proxmox_api_tokens_info] CHECK CONSTRAINT [FK_proxmox_api_tokens_info]
GO
