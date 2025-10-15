import logging
import requests
import time
from typing import Dict, List, Optional, Any
from datetime import datetime
from elasticsearch.exceptions import RequestError, NotFoundError

logger = logging.getLogger(__name__)

class KibanaSampleDataLoader:
    """Manages Kibana sample datasets for SIEM demonstration"""
    
    def __init__(self, kibana_url: str, elasticsearch_client, username: str = "elastic", password: str = "changeme"):
        """Initialize Kibana sample data loader"""
        self.kibana_url = kibana_url.rstrip('/')
        self.es_client = elasticsearch_client
        self.auth = (username, password)
        self.session = requests.Session()
        self.session.auth = self.auth
        
        # Define available sample datasets
        self.sample_datasets = {
            'logs': {
                'id': 'logs',
                'name': 'Sample web logs',
                'description': 'Web server logs with security events',
                'index': 'kibana_sample_data_logs',
                'security_relevant': True
            },
            'ecommerce': {
                'id': 'ecommerce', 
                'name': 'Sample eCommerce orders',
                'description': 'E-commerce transaction data',
                'index': 'kibana_sample_data_ecommerce',
                'security_relevant': False
            },
            'flights': {
                'id': 'flights',
                'name': 'Sample flight data',
                'description': 'Flight delay and cancellation data',
                'index': 'kibana_sample_data_flights', 
                'security_relevant': False
            }
        }
    
    def check_kibana_availability(self) -> bool:
        """Check if Kibana is available and accessible"""
        try:
            response = self.session.get(
                f"{self.kibana_url}/api/status",
                timeout=10,
                headers={'kbn-xsrf': 'true'}
            )
            
            if response.status_code == 200:
                status_data = response.json()
                overall_status = status_data.get('status', {}).get('overall', {}).get('level')
                
                if overall_status in ['available', 'degraded']:
                    logger.info(f"Kibana is available (status: {overall_status})")
                    return True
                else:
                    logger.warning(f"Kibana status is {overall_status}")
                    return False
            else:
                logger.error(f"Kibana health check failed: HTTP {response.status_code}")
                return False
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to connect to Kibana: {str(e)}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error checking Kibana availability: {str(e)}")
            return False
    
    def get_installed_sample_data(self) -> List[Dict[str, Any]]:
        """Get list of currently installed sample datasets"""
        try:
            response = self.session.get(
                f"{self.kibana_url}/api/sample_data",
                timeout=30,
                headers={'kbn-xsrf': 'true'}
            )
            
            if response.status_code == 200:
                sample_data = response.json()
                
                # Check which datasets are installed by verifying indices exist
                installed_datasets = []
                for dataset in sample_data:
                    dataset_id = dataset.get('id')
                    index_name = dataset.get('dataIndices', [{}])[0].get('id', '')
                    
                    if index_name:
                        try:
                            # Check if index exists in Elasticsearch
                            if self.es_client.client.indices.exists(index=index_name):
                                doc_count = self.es_client.count_documents(index_name)
                                dataset['installed'] = True
                                dataset['document_count'] = doc_count
                                dataset['index_name'] = index_name
                            else:
                                dataset['installed'] = False
                                dataset['document_count'] = 0
                                dataset['index_name'] = index_name
                        except Exception as e:
                            logger.warning(f"Failed to check index {index_name}: {str(e)}")
                            dataset['installed'] = False
                            dataset['document_count'] = 0
                    
                    installed_datasets.append(dataset)
                
                return installed_datasets
            else:
                logger.error(f"Failed to get sample data list: HTTP {response.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"Error getting installed sample data: {str(e)}")
            return []
    
    def install_sample_dataset(self, dataset_id: str) -> bool:
        """Install a specific sample dataset"""
        try:
            if dataset_id not in self.sample_datasets:
                logger.error(f"Unknown dataset ID: {dataset_id}")
                return False
            
            dataset_info = self.sample_datasets[dataset_id]
            logger.info(f"Installing sample dataset: {dataset_info['name']}")
            
            # Install via Kibana API
            response = self.session.post(
                f"{self.kibana_url}/api/sample_data/{dataset_id}",
                timeout=120,  # Installation can take time
                headers={'kbn-xsrf': 'true'}
            )
            
            if response.status_code in [200, 204]:
                logger.info(f"Successfully installed dataset: {dataset_info['name']}")
                
                # Wait for data to be indexed
                time.sleep(5)
                
                # Verify installation
                index_name = dataset_info['index']
                max_retries = 10
                retry_count = 0
                
                while retry_count < max_retries:
                    try:
                        if self.es_client.client.indices.exists(index=index_name):
                            doc_count = self.es_client.count_documents(index_name)
                            if doc_count > 0:
                                logger.info(f"Dataset verification successful: {doc_count} documents indexed")
                                return True
                    except Exception as e:
                        logger.warning(f"Verification attempt {retry_count + 1} failed: {str(e)}")
                    
                    retry_count += 1
                    time.sleep(2)
                
                logger.warning(f"Dataset installed but verification failed for {dataset_id}")
                return True  # Consider successful even if verification failed
                
            else:
                error_msg = f"Failed to install dataset {dataset_id}: HTTP {response.status_code}"
                if response.text:
                    error_msg += f" - {response.text}"
                logger.error(error_msg)
                return False
                
        except Exception as e:
            logger.error(f"Error installing sample dataset {dataset_id}: {str(e)}")
            return False
    
    def uninstall_sample_dataset(self, dataset_id: str) -> bool:
        """Uninstall a specific sample dataset"""
        try:
            if dataset_id not in self.sample_datasets:
                logger.error(f"Unknown dataset ID: {dataset_id}")
                return False
            
            dataset_info = self.sample_datasets[dataset_id]
            logger.info(f"Uninstalling sample dataset: {dataset_info['name']}")
            
            # Uninstall via Kibana API
            response = self.session.delete(
                f"{self.kibana_url}/api/sample_data/{dataset_id}",
                timeout=60,
                headers={'kbn-xsrf': 'true'}
            )
            
            if response.status_code in [200, 204, 404]:
                logger.info(f"Successfully uninstalled dataset: {dataset_info['name']}")
                return True
            else:
                logger.error(f"Failed to uninstall dataset {dataset_id}: HTTP {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Error uninstalling sample dataset {dataset_id}: {str(e)}")
            return False
    
    def install_security_datasets(self) -> Dict[str, bool]:
        """Install all security-relevant sample datasets"""
        results = {}
        
        for dataset_id, dataset_info in self.sample_datasets.items():
            if dataset_info['security_relevant']:
                logger.info(f"Installing security dataset: {dataset_info['name']}")
                results[dataset_id] = self.install_sample_dataset(dataset_id)
            else:
                logger.info(f"Skipping non-security dataset: {dataset_info['name']}")
                results[dataset_id] = False
        
        return results
    
    def install_all_datasets(self) -> Dict[str, bool]:
        """Install all available sample datasets"""
        results = {}
        
        for dataset_id in self.sample_datasets.keys():
            results[dataset_id] = self.install_sample_dataset(dataset_id)
        
        return results
    
    def create_custom_security_data(self) -> bool:
        """Create custom security event data for demonstration"""
        try:
            custom_index = "siem-demo-security-events"
            
            # Define index mapping for security events
            mapping = {
                "mappings": {
                    "properties": {
                        "@timestamp": {"type": "date"},
                        "event": {
                            "properties": {
                                "category": {"type": "keyword"},
                                "type": {"type": "keyword"},
                                "action": {"type": "keyword"},
                                "outcome": {"type": "keyword"},
                                "severity": {"type": "long"},
                                "code": {"type": "keyword"}
                            }
                        },
                        "source": {
                            "properties": {
                                "ip": {"type": "ip"},
                                "hostname": {"type": "keyword"},
                                "user": {
                                    "properties": {
                                        "name": {"type": "keyword"},
                                        "domain": {"type": "keyword"}
                                    }
                                }
                            }
                        },
                        "destination": {
                            "properties": {
                                "ip": {"type": "ip"},
                                "hostname": {"type": "keyword"},
                                "port": {"type": "long"}
                            }
                        },
                        "process": {
                            "properties": {
                                "name": {"type": "keyword"},
                                "pid": {"type": "long"},
                                "command_line": {"type": "text"}
                            }
                        },
                        "message": {"type": "text"},
                        "tags": {"type": "keyword"}
                    }
                }
            }
            
            # Create index if it doesn't exist
            if not self.es_client.client.indices.exists(index=custom_index):
                self.es_client.client.indices.create(index=custom_index, body=mapping)
                logger.info(f"Created custom security index: {custom_index}")
            
            # Sample security events
            security_events = [
                {
                    "@timestamp": datetime.now().isoformat(),
                    "event": {
                        "category": "authentication",
                        "type": "start",
                        "action": "logon",
                        "outcome": "failure",
                        "severity": 8,
                        "code": "4625"
                    },
                    "source": {
                        "ip": "192.168.1.100",
                        "hostname": "workstation-01",
                        "user": {
                            "name": "admin",
                            "domain": "CORP"
                        }
                    },
                    "message": "Failed login attempt for user admin",
                    "tags": ["authentication", "failed_login", "suspicious"]
                },
                {
                    "@timestamp": datetime.now().isoformat(),
                    "event": {
                        "category": "process",
                        "type": "start",
                        "action": "exec",
                        "outcome": "success",
                        "severity": 12,
                        "code": "4688"
                    },
                    "source": {
                        "hostname": "server-01"
                    },
                    "process": {
                        "name": "powershell.exe",
                        "pid": 1234,
                        "command_line": "powershell.exe -enc <suspicious_base64>"
                    },
                    "message": "Suspicious PowerShell execution detected",
                    "tags": ["process", "powershell", "encoded", "malicious"]
                }
            ]
            
            # Index sample events
            for i, event in enumerate(security_events):
                self.es_client.client.index(
                    index=custom_index,
                    id=f"demo-event-{i+1}",
                    body=event
                )
            
            # Refresh index
            self.es_client.client.indices.refresh(index=custom_index)
            
            logger.info(f"Created {len(security_events)} custom security events")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create custom security data: {str(e)}")
            return False
    
    def get_sample_data_status(self) -> Dict[str, Any]:
        """Get comprehensive status of sample data"""
        try:
            status = {
                'kibana_available': self.check_kibana_availability(),
                'installed_datasets': [],
                'total_documents': 0,
                'security_datasets': 0,
                'last_check': datetime.now().isoformat()
            }
            
            if status['kibana_available']:
                installed = self.get_installed_sample_data()
                status['installed_datasets'] = installed
                
                for dataset in installed:
                    if dataset.get('installed', False):
                        doc_count = dataset.get('document_count', 0)
                        status['total_documents'] += doc_count
                        
                        # Check if it's a security-relevant dataset
                        dataset_id = dataset.get('id', '')
                        if dataset_id in self.sample_datasets and self.sample_datasets[dataset_id]['security_relevant']:
                            status['security_datasets'] += 1
            
            return status
            
        except Exception as e:
            logger.error(f"Failed to get sample data status: {str(e)}")
            return {
                'kibana_available': False,
                'error': str(e),
                'last_check': datetime.now().isoformat()
            }
