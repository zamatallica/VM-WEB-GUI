from diagrams import Diagram, Cluster
from diagrams.onprem.compute import Server
from diagrams.onprem.client import User
from diagrams.onprem.network import Nginx
from diagrams.programming.language import Python, Nodejs
from diagrams.generic.virtualization import Virtualbox
from diagrams.onprem.database import MSSQL
from diagrams.onprem.monitoring import Prometheus
from diagrams.onprem.container import Docker
from diagrams.onprem.iac import Ansible

with Diagram("Full Infrastructure Architecture", show=True):
    user = User("Client")

    # Web Application Cluster
    with Cluster("Web Application"):
        nginx = Nginx("Nginx Reverse Proxy")
        flask = Python("Flask Backend")
        node = Nodejs("Node.js WebSocket Proxy")

    # Proxmox and VNC Cluster
    with Cluster("Proxmox Infrastructure"):
        proxmox = Virtualbox("Proxmox Server")
        vnc = Server("VNC Session")

    # SQL Server Cluster
    with Cluster("SQL Server Infrastructure"):
        primary_sql = MSSQL("Primary SQL Server")
        secondary_sql = MSSQL("Secondary SQL Server")
        ha_sql = MSSQL("High Availability Replica")
        replication_sql = MSSQL("Replication DB")
        monitoring = Prometheus("SQL Performance Monitoring")
        
    # SQL Ops Support (Automation & Monitoring)
    with Cluster("Operations Support"):
        ansible = Ansible("Automated DB Deployment")
        docker = Docker("SQL Server Containers")

    # Web Application Flow
    user >> nginx >> flask
    flask >> node
    node >> proxmox >> vnc

    # SQL Server Architecture Flow
    primary_sql - ha_sql
    primary_sql - secondary_sql
    primary_sql >> replication_sql
    primary_sql >> monitoring

    # SQL Ops Support
    ansible >> [primary_sql, secondary_sql, ha_sql, replication_sql]
    docker >> primary_sql
