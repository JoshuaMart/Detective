package pipeline

// top30Ports are the 30 most commonly open TCP ports for web-facing infrastructure.
var top30Ports = []int{
	21,    // FTP
	22,    // SSH
	23,    // Telnet
	80,    // HTTP
	443,   // HTTPS
	1433,  // MSSQL
	1521,  // Oracle
	2049,  // NFS
	3306,  // MySQL
	3389,  // RDP
	4443,  // HTTPS alt
	5432,  // PostgreSQL
	5672,  // RabbitMQ
	5900,  // VNC
	6379,  // Redis
	6443,  // Kubernetes API
	8080,  // HTTP alt
	8443,  // HTTPS alt
	8888,  // HTTP alt
	9090,  // Prometheus / HTTP alt
	9200,  // Elasticsearch
	11211, // Memcached
	15672, // RabbitMQ Management
	27017, // MongoDB
}
