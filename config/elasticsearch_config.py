import os
from dataclasses import dataclass
from typing import Dict, List, Optional
from dotenv import load_dotenv

load_dotenv()

@dataclass
class ElasticsearchConfig:
    """Elasticsearch connection configuration"""
    hosts: List[str]
    username: Optional[str] = None
    password: Optional[str] = None
    api_key: Optional[str] = None
    ca_certs: Optional[str] = None
    verify_certs: bool = True
    timeout: int = 30
    max_retries: int = 3
    retry_on_timeout: bool = True
    sniff_on_start: bool = False
    sniff_on_connection_fail: bool = True
    sniffer_timeout: int = 60
    connection_pool_size: int = 10
    max_connections_per_node: int = 10
    
    @classmethod
    def from_environment(cls) -> 'ElasticsearchConfig':
        """Create configuration from environment variables"""
        try:
            # Default configuration
            hosts = os.getenv('ELASTICSEARCH_HOSTS', 'localhost:9200').split(',')
            hosts = [host.strip() for host in hosts]
            
            # Authentication
            username = os.getenv('ELASTICSEARCH_USERNAME')
            password = os.getenv('ELASTICSEARCH_PASSWORD') 
            api_key = os.getenv('ELASTICSEARCH_API_KEY')
            
            # SSL/TLS
            ca_certs = os.getenv('ELASTICSEARCH_CA_CERTS')
            verify_certs = os.getenv('ELASTICSEARCH_VERIFY_CERTS', 'true').lower() == 'true'
            
            # Connection settings
            timeout = int(os.getenv('ELASTICSEARCH_TIMEOUT', '30'))
            max_retries = int(os.getenv('ELASTICSEARCH_MAX_RETRIES', '3'))
            retry_on_timeout = os.getenv('ELASTICSEARCH_RETRY_ON_TIMEOUT', 'true').lower() == 'true'
            
            # Connection pool settings
            connection_pool_size = int(os.getenv('ELASTICSEARCH_POOL_SIZE', '10'))
            max_connections_per_node = int(os.getenv('ELASTICSEARCH_MAX_CONNECTIONS_PER_NODE', '10'))
            
            return cls(
                hosts=hosts,
                username=username,
                password=password,
                api_key=api_key,
                ca_certs=ca_certs,
                verify_certs=verify_certs,
                timeout=timeout,
                max_retries=max_retries,
                retry_on_timeout=retry_on_timeout,
                connection_pool_size=connection_pool_size,
                max_connections_per_node=max_connections_per_node
            )
        except Exception as e:
            raise ValueError(f"Failed to load Elasticsearch configuration: {str(e)}")
    
    @classmethod
    def get_development_config(cls) -> 'ElasticsearchConfig':
        """Get development configuration for local testing"""
        return cls(
            hosts=['localhost:9200'],
            username='elastic',
            password='changeme',
            verify_certs=False,
            sniff_on_start=True,
            sniff_on_connection_fail=True
        )
    
    @classmethod
    def get_cloud_config(cls, cloud_id: str, username: str, password: str) -> 'ElasticsearchConfig':
        """Get configuration for Elastic Cloud"""
        return cls(
            hosts=[],  # Will be set from cloud_id
            username=username,
            password=password,
            verify_certs=True,
            sniff_on_start=False,
            sniff_on_connection_fail=False
        )
    
    def to_dict(self) -> Dict:
        """Convert configuration to dictionary for Elasticsearch client"""
        config = {
            'hosts': self.hosts,
            'timeout': self.timeout,
            'max_retries': self.max_retries,
            'retry_on_timeout': self.retry_on_timeout,
            'sniff_on_start': self.sniff_on_start,
            'sniff_on_connection_fail': self.sniff_on_connection_fail,
            'sniffer_timeout': self.sniffer_timeout,
            'maxsize': self.connection_pool_size,
            'connections_per_node': self.max_connections_per_node
        }
        
        # Authentication
        if self.api_key:
            config['api_key'] = self.api_key
        elif self.username and self.password:
            config['basic_auth'] = (self.username, self.password)
        
        # SSL/TLS
        if self.ca_certs:
            config['ca_certs'] = self.ca_certs
        config['verify_certs'] = self.verify_certs
        
        return {k: v for k, v in config.items() if v is not None}

# Security indices commonly used in SIEM environments
SECURITY_INDICES = {
    'winlogbeat': 'winlogbeat-*',
    'auditbeat': 'auditbeat-*',
    'filebeat': 'filebeat-*',
    'packetbeat': 'packetbeat-*',
    'metricbeat': 'metricbeat-*',
    'heartbeat': 'heartbeat-*',
    'kibana_sample_data_logs': 'kibana_sample_data_logs',
    'kibana_sample_data_flights': 'kibana_sample_data_flights',
    'kibana_sample_data_ecommerce': 'kibana_sample_data_ecommerce',
    'security_events': 'security-events-*',
    'wazuh_alerts': 'wazuh-alerts-*',
    'suricata': 'suricata-*',
    'zeek': 'zeek-*'
}

# Common security field mappings
SECURITY_FIELD_MAPPINGS = {
    'timestamp_fields': [
        '@timestamp',
        'timestamp',
        'event.created',
        'event.start',
        'event.end',
        'log.offset'
    ],
    'ip_fields': [
        'source.ip',
        'destination.ip',
        'client.ip',
        'server.ip',
        'host.ip',
        'network.forwarded_ip'
    ],
    'user_fields': [
        'user.name',
        'user.id', 
        'user.domain',
        'user.email',
        'source.user.name',
        'destination.user.name'
    ],
    'host_fields': [
        'host.name',
        'host.hostname',
        'agent.hostname',
        'source.hostname',
        'destination.hostname'
    ],
    'process_fields': [
        'process.name',
        'process.executable',
        'process.command_line',
        'process.pid',
        'process.parent.name'
    ],
    'event_fields': [
        'event.category',
        'event.type',
        'event.action',
        'event.outcome',
        'event.severity',
        'event.code'
    ]
}

