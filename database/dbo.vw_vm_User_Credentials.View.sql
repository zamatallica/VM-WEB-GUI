USE [webInterface]
GO
/****** Object:  View [dbo].[vw_vm_User_Credentials]    Script Date: 3/25/2025 1:44:36 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE VIEW [dbo].[vw_vm_User_Credentials]
AS
SELECT        u.UserId, u.Username AS account_username, vuc.vm_username AS credential_username, vuc.vm_user_password_hash, dom.domain_name, auth.auth_method_name, vuc.vm_last_logon, vuc.vm_id AS credential_vm_id, 
                         vm.proxmox_vm_name, vm.proxmox_vm_id, uvm.vm_id AS access_vm_id, uvm.role_id AS user_vm_role, vuc.vm_credential_id
FROM            dbo.VM_user_credentials AS vuc INNER JOIN
                         dbo.users AS u ON u.UserId = vuc.userid LEFT OUTER JOIN
                         dbo.VMs AS vm ON vm.vm_id = vuc.vm_id INNER JOIN
                         dbo.OS_type AS os ON os.os_id = vuc.os_id INNER JOIN
                         dbo.VM_logon_domains AS dom ON dom.domain_id = vuc.domain_id INNER JOIN
                         dbo.authentication_method AS auth ON auth.auth_method_id = vuc.auth_method_id LEFT OUTER JOIN
                         dbo.vw_UserVMs AS uvm ON uvm.vm_id = vuc.vm_id AND uvm.UserId = u.UserId
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPane1', @value=N'[0E232FF0-B466-11cf-A24F-00AA00A3EFFF, 1.00]
Begin DesignProperties = 
   Begin PaneConfigurations = 
      Begin PaneConfiguration = 0
         NumPanes = 4
         Configuration = "(H (1[40] 4[20] 2[20] 3) )"
      End
      Begin PaneConfiguration = 1
         NumPanes = 3
         Configuration = "(H (1 [50] 4 [25] 3))"
      End
      Begin PaneConfiguration = 2
         NumPanes = 3
         Configuration = "(H (1 [50] 2 [25] 3))"
      End
      Begin PaneConfiguration = 3
         NumPanes = 3
         Configuration = "(H (4 [30] 2 [40] 3))"
      End
      Begin PaneConfiguration = 4
         NumPanes = 2
         Configuration = "(H (1 [56] 3))"
      End
      Begin PaneConfiguration = 5
         NumPanes = 2
         Configuration = "(H (2 [66] 3))"
      End
      Begin PaneConfiguration = 6
         NumPanes = 2
         Configuration = "(H (4 [50] 3))"
      End
      Begin PaneConfiguration = 7
         NumPanes = 1
         Configuration = "(V (3))"
      End
      Begin PaneConfiguration = 8
         NumPanes = 3
         Configuration = "(H (1[56] 4[18] 2) )"
      End
      Begin PaneConfiguration = 9
         NumPanes = 2
         Configuration = "(H (1 [75] 4))"
      End
      Begin PaneConfiguration = 10
         NumPanes = 2
         Configuration = "(H (1[66] 2) )"
      End
      Begin PaneConfiguration = 11
         NumPanes = 2
         Configuration = "(H (4 [60] 2))"
      End
      Begin PaneConfiguration = 12
         NumPanes = 1
         Configuration = "(H (1) )"
      End
      Begin PaneConfiguration = 13
         NumPanes = 1
         Configuration = "(V (4))"
      End
      Begin PaneConfiguration = 14
         NumPanes = 1
         Configuration = "(V (2))"
      End
      ActivePaneConfig = 0
   End
   Begin DiagramPane = 
      Begin Origin = 
         Top = 0
         Left = 0
      End
      Begin Tables = 
         Begin Table = "vuc"
            Begin Extent = 
               Top = 6
               Left = 38
               Bottom = 136
               Right = 256
            End
            DisplayFlags = 280
            TopColumn = 0
         End
         Begin Table = "u"
            Begin Extent = 
               Top = 6
               Left = 294
               Bottom = 136
               Right = 464
            End
            DisplayFlags = 280
            TopColumn = 0
         End
         Begin Table = "vm"
            Begin Extent = 
               Top = 138
               Left = 38
               Bottom = 268
               Right = 232
            End
            DisplayFlags = 280
            TopColumn = 0
         End
         Begin Table = "os"
            Begin Extent = 
               Top = 138
               Left = 270
               Bottom = 234
               Right = 440
            End
            DisplayFlags = 280
            TopColumn = 0
         End
         Begin Table = "dom"
            Begin Extent = 
               Top = 234
               Left = 270
               Bottom = 347
               Right = 440
            End
            DisplayFlags = 280
            TopColumn = 0
         End
         Begin Table = "auth"
            Begin Extent = 
               Top = 270
               Left = 38
               Bottom = 366
               Right = 233
            End
            DisplayFlags = 280
            TopColumn = 0
         End
         Begin Table = "uvm"
            Begin Extent = 
               Top = 348
               Left = 271
               Bottom = 478
               Right = 465
            End
            DisplayFlags = 280
            TopColumn = 0
   ' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_vm_User_Credentials'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPane2', @value=N'      End
      End
   End
   Begin SQLPane = 
   End
   Begin DataPane = 
      Begin ParameterDefaults = ""
      End
   End
   Begin CriteriaPane = 
      Begin ColumnWidths = 11
         Column = 1440
         Alias = 900
         Table = 1170
         Output = 720
         Append = 1400
         NewValue = 1170
         SortType = 1350
         SortOrder = 1410
         GroupBy = 1350
         Filter = 1350
         Or = 1350
         Or = 1350
         Or = 1350
      End
   End
End
' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_vm_User_Credentials'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPaneCount', @value=2 , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_vm_User_Credentials'
GO
