USE [webInterface]
GO
/****** Object:  Table [dbo].[VM_OS_details]    Script Date: 3/25/2025 1:44:36 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[VM_OS_details](
	[vm_id] [int] NOT NULL,
	[os_id] [int] NOT NULL,
	[vm_os_short_name] [varchar](50) NULL,
	[vm_os_version] [varchar](50) NULL,
PRIMARY KEY CLUSTERED 
(
	[vm_id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
ALTER TABLE [dbo].[VM_OS_details]  WITH CHECK ADD FOREIGN KEY([os_id])
REFERENCES [dbo].[OS_type] ([os_id])
GO
